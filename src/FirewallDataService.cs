using NetFwTypeLib;
using System.IO;
using System.Linq;
using MinimalFirewall.TypedObjects;
using System.Collections.Generic;
using Microsoft.Extensions.Caching.Memory;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System;
using System.Net;

namespace MinimalFirewall
{
    public enum MfwRuleStatus { None, MfwAllow, MfwBlock }

    public class FirewallDataService(FirewallRuleService firewallRuleService, WildcardRuleService wildcardRuleService, UwpService uwpService, RuleTimestampService ruleTimestampService)
    {
        private readonly FirewallRuleService _firewallRuleService = firewallRuleService;
        private readonly WildcardRuleService _wildcardRuleService = wildcardRuleService;
        private readonly UwpService _uwpService = uwpService;
        private readonly RuleTimestampService _ruleTimestampService = ruleTimestampService;
        private readonly MemoryCache _localCache = new(new MemoryCacheOptions());
        private const string ServicesCacheKey = "ServicesList";
        private const string MfwRulesCacheKey = "MfwRulesList";
        private const string AggregatedRulesCacheKey = "AggregatedRulesList";
        private static readonly char[] _separators = [',', ' '];

        public void ClearAggregatedRulesCache()
        {
            _localCache.Remove(AggregatedRulesCacheKey);
        }

        public void InvalidateRuleCache()
        {
            _localCache.Remove(MfwRulesCacheKey);
            _localCache.Remove(AggregatedRulesCacheKey);
        }

        public List<ServiceViewModel> GetCachedServicesWithExePaths()
        {
            if (_localCache.TryGetValue(ServicesCacheKey, out List<ServiceViewModel>? services) && services != null)
            {
                return services;
            }

            services = SystemDiscoveryService.GetServicesWithExePaths();
            var cacheOptions = new MemoryCacheEntryOptions()
                 .SetSlidingExpiration(TimeSpan.FromMinutes(10));
            _localCache.Set(ServicesCacheKey, services, cacheOptions);
            return services;
        }

        public List<UwpApp> LoadUwpAppsFromCache()
        {
            return _uwpService.LoadUwpAppsFromCache();
        }

        private Task<List<AdvancedRuleViewModel>> FetchAllMfwRulesAsync(CancellationToken token)
        {
            return Task.Run(() =>
            {
                // process and immediately destroys the COM object.
                var mfwRules = _firewallRuleService.GetAllRulesMapped(CreateAdvancedRuleViewModel);

                if (token.IsCancellationRequested)
                {
                    return [];
                }

                // Stamp first-seen times, prune stale entries, persist if dirty.
                // First refresh after install treats all observed rules as baseline (Unknown).
                var now = DateTime.UtcNow;
                bool isBaseline = _ruleTimestampService.IsBaselineSession;
                var activeNames = new List<string>(mfwRules.Count);
                foreach (var rule in mfwRules)
                {
                    if (string.IsNullOrEmpty(rule.Name)) continue;
                    rule.DateAdded = _ruleTimestampService.EnsureStamped(rule.Name, now, isBaseline);
                    activeNames.Add(rule.Name);
                }
                _ruleTimestampService.PruneTo(activeNames);
                _ruleTimestampService.Flush();
                if (isBaseline) _ruleTimestampService.EndBaselineSession();

                return mfwRules;
            }, token);
        }

        private static string MergeDistinct(IEnumerable<string> items)
        {
            var distinctItems = items.Where(p => !string.IsNullOrEmpty(p) && p != "*").Distinct().ToList();
            return distinctItems.Count > 0 ? string.Join(", ", distinctItems) : "*";
        }

        public async Task<List<AdvancedRuleViewModel>> GetMfwRulesAsync(CancellationToken token)
        {
            var result = await _localCache.GetOrCreateAsync(MfwRulesCacheKey, async entry =>
            {
                entry.SlidingExpiration = TimeSpan.FromMinutes(10);
                return await FetchAllMfwRulesAsync(token);
            });

            return result ?? [];
        }

        public async Task<List<AggregatedRuleViewModel>> GetAggregatedRulesAsync(CancellationToken token, IProgress<int>? progress = null)
        {
            if (_localCache.TryGetValue(AggregatedRulesCacheKey, out List<AggregatedRuleViewModel>? cachedRules) && cachedRules != null)
            {
                progress?.Report(100);
                return cachedRules;
            }

            var allMfwRules = await GetMfwRulesAsync(token);
            if (token.IsCancellationRequested) return [];

            var aggregatedRules = await Task.Run(() =>
            {
                int totalRules = allMfwRules.Count;
                if (totalRules == 0)
                {
                    progress?.Report(100);
                    return new List<AggregatedRuleViewModel>();
                }

                var groupedByGroupingAndProtocol = allMfwRules
                    .Where(r => r.IsEnabled)
                    .GroupBy(r => (r.Grouping, r.ApplicationName, r.ServiceName, r.Protocol))
                    .ToList();

                var aggRules = new List<AggregatedRuleViewModel>();
                int processedCount = 0;

                foreach (var group in groupedByGroupingAndProtocol)
                {
                    if (token.IsCancellationRequested) return [];
                    var groupList = group.ToList();
                    aggRules.Add(CreateAggregatedViewModelForRuleGroup(groupList));
                    processedCount += groupList.Count;
                    progress?.Report((processedCount * 100) / totalRules);
                }

                progress?.Report(100);
                return aggRules.OrderBy(r => r.Name).ToList();
            }, token);

            if (token.IsCancellationRequested) return [];

            var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));
            _localCache.Set(AggregatedRulesCacheKey, aggregatedRules, cacheEntryOptions);

            return aggregatedRules;
        }

        private static AggregatedRuleViewModel CreateAggregatedViewModelForRuleGroup(List<AdvancedRuleViewModel> group)
        {
            var firstRule = group[0];
            var commonName = GetCommonName(group);
            if (string.IsNullOrEmpty(commonName) || commonName.StartsWith('@'))
            {
                commonName = firstRule.Grouping ?? string.Empty;
            }

            var aggRule = new AggregatedRuleViewModel
            {
                Name = commonName,
                ApplicationName = firstRule.ApplicationName ?? string.Empty,
                ServiceName = firstRule.ServiceName ?? string.Empty,
                Protocol = firstRule.Protocol,
                ProtocolName = GetProtocolName(firstRule.Protocol),
                Type = DetermineRuleType(firstRule),
                UnderlyingRules = [.. group],
                IsEnabled = group.TrueForAll(r => r.IsEnabled),
                Profiles = firstRule.Profiles,
                Grouping = firstRule.Grouping ?? "",
                Description = firstRule.Description ?? "",
                DateAdded = group.Where(r => r.DateAdded.HasValue).Min(r => (DateTime?)r.DateAdded),
                AutoAllowedPublisher = group.Select(r => r.AutoAllowedPublisher).FirstOrDefault(p => !string.IsNullOrEmpty(p)) ?? ""
            };

            bool hasInAllow = group.Exists(r => r.Status == "Allow" && r.Direction.HasFlag(Directions.Incoming));
            bool hasOutAllow = group.Exists(r => r.Status == "Allow" && r.Direction.HasFlag(Directions.Outgoing));
            bool hasInBlock = group.Exists(r => r.Status == "Block" && r.Direction.HasFlag(Directions.Incoming));
            bool hasOutBlock = group.Exists(r => r.Status == "Block" && r.Direction.HasFlag(Directions.Outgoing));

            aggRule.InboundStatus = hasInAllow ? "Allow" : (hasInBlock ? "Block" : "-");
            if (hasInAllow && hasInBlock) aggRule.InboundStatus = "Allow, Block";

            aggRule.OutboundStatus = hasOutAllow ? "Allow" : (hasOutBlock ? "Block" : "-");
            if (hasOutAllow && hasOutBlock) aggRule.OutboundStatus = "Allow, Block";

            aggRule.LocalPorts = MergeDistinct(group.Select(r => r.LocalPorts));
            aggRule.RemotePorts = MergeDistinct(group.Select(r => r.RemotePorts));
            aggRule.LocalAddresses = MergeDistinct(group.Select(r => r.LocalAddresses));
            aggRule.RemoteAddresses = MergeDistinct(group.Select(r => r.RemoteAddresses));

            return aggRule;
        }

        private static string GetCommonName(List<AdvancedRuleViewModel> group)
        {
            if (group.Count == 0) return string.Empty;
            if (group.Count == 1) return group[0].Name ?? string.Empty;

            var names = group.Select(r => r.Name ?? string.Empty).ToList();
            string first = names[0];
            int commonPrefixLength = first.Length;

            foreach (string name in names.Skip(1))
            {
                commonPrefixLength = Math.Min(commonPrefixLength, name.Length);
                for (int i = 0; i < commonPrefixLength; i++)
                {
                    if (first[i] != name[i])
                    {
                        commonPrefixLength = i;
                        break;
                    }
                }
            }

            string commonPrefix = first[..commonPrefixLength].Trim();
            if (commonPrefix.EndsWith('-') || commonPrefix.EndsWith('('))
            {
                commonPrefix = commonPrefix[..^1].Trim();
            }

            return string.IsNullOrEmpty(commonPrefix) ? (group[0].Grouping ?? string.Empty) : commonPrefix;
        }


        private static RuleType DetermineRuleType(AdvancedRuleViewModel rule)
        {
            if ((rule.Description != null && rule.Description.StartsWith(MFWConstants.UwpDescriptionPrefix, StringComparison.Ordinal)) ||
                 (rule.ApplicationName != null && rule.ApplicationName.StartsWith('@')) ||
                (rule.Name != null && rule.Name.StartsWith('@')))
            {
                return RuleType.UWP;
            }

            if (!string.IsNullOrEmpty(rule.ServiceName) && rule.ServiceName != "*")
                return RuleType.Service;

            if (!string.IsNullOrEmpty(rule.ApplicationName) && rule.ApplicationName != "*")
            {
                bool hasSpecifics = (!string.IsNullOrEmpty(rule.LocalPorts) && rule.LocalPorts != "*") ||
                                     (!string.IsNullOrEmpty(rule.RemotePorts) && rule.RemotePorts != "*") ||
                                     (!string.IsNullOrEmpty(rule.LocalAddresses) && rule.LocalAddresses != "*") ||
                                     (!string.IsNullOrEmpty(rule.RemoteAddresses) && rule.RemoteAddresses != "*");
                return hasSpecifics ? RuleType.Advanced : RuleType.Program;
            }
            return RuleType.Advanced;
        }

        private static string GetStr(string? val, string def) => string.IsNullOrEmpty(val) ? def : val;

        public async Task<MfwRuleStatus> CheckMfwRuleStatusAsync(PendingConnectionViewModel pending)
        {
            if (!Enum.TryParse<Directions>(pending.Direction, true, out var dirEnum))
            {
                Debug.WriteLine($"[CheckMfwRuleStatus] Invalid direction: {pending.Direction}");
                return MfwRuleStatus.None;
            }

            string normalizedAppPath = string.IsNullOrEmpty(pending.AppPath) ? string.Empty : PathResolver.NormalizePath(pending.AppPath);
            var serviceNamesSet = string.IsNullOrEmpty(pending.ServiceName)
                 ? null
                : new HashSet<string>(pending.ServiceName.Split(_separators, StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);

            var mfwRules = await GetMfwRulesAsync(CancellationToken.None);

            if (mfwRules == null)
            {
                Debug.WriteLine("[ERROR] CheckMfwRuleStatus: GetMfwRulesAsync() returned null unexpectedly.");
                return MfwRuleStatus.None;
            }

            bool foundAllow = false;
            bool foundBlock = false;

            bool eventHasService = serviceNamesSet != null && serviceNamesSet.Count > 0;
            bool eventHasApp = !string.IsNullOrEmpty(normalizedAppPath);

            // Parse event protocol for matching
            int eventProtocol = 0;
            if (!string.IsNullOrEmpty(pending.Protocol) && int.TryParse(pending.Protocol, out int parsedProto))
            {
                eventProtocol = parsedProto;
            }

            foreach (var rule in mfwRules)
            {
                if (rule == null) continue;

                // Ignore disabled rules
                if (!rule.IsEnabled) continue;

                // Must match direction
                if (!rule.Direction.HasFlag(dirEnum)) continue;

                bool ruleHasService = !string.IsNullOrEmpty(rule.ServiceName) && rule.ServiceName != "*";
                bool ruleHasApp = !string.IsNullOrEmpty(rule.ApplicationName) && rule.ApplicationName != "*";

                bool match = false;

                // Match app/service target
                if (eventHasService)
                {
                    if (ruleHasService && serviceNamesSet!.Contains(rule.ServiceName))
                    {
                        match = !ruleHasApp || (eventHasApp && string.Equals(rule.ApplicationName, normalizedAppPath, StringComparison.OrdinalIgnoreCase));
                    }
                }
                else if (!ruleHasService && ruleHasApp && eventHasApp)
                {
                    match = string.Equals(rule.ApplicationName, normalizedAppPath, StringComparison.OrdinalIgnoreCase);
                }

                if (!match) continue;

                // Conservative protocol matching
                // Protocol 256 (Any) matches all protocols
                // Specific protocol must match exactly
                if (rule.Protocol != 256 && rule.Protocol != eventProtocol)
                {
                    continue;
                }

                // Conservative port matching
                // * ports match all
                // Specific ports must match (event port must be in rule's port list)
                // If rule has specific ports but event value is empty, rule does NOT match
                if (!string.IsNullOrEmpty(rule.RemotePorts) && rule.RemotePorts != "*")
                {
                    if (string.IsNullOrEmpty(pending.RemotePort) || pending.RemotePort == "*")
                    {
                        // Rule has specific ports but event doesn't - cannot confirm match
                        continue;
                    }
                    bool portMatch = rule.RemotePorts.Split(_separators, StringSplitOptions.RemoveEmptyEntries)
                        .Any(p => PortMatches(p.Trim(), pending.RemotePort));
                    if (!portMatch) continue;
                }

                if (!string.IsNullOrEmpty(rule.LocalPorts) && rule.LocalPorts != "*")
                {
                    if (string.IsNullOrEmpty(pending.LocalPort) || pending.LocalPort == "*")
                    {
                        // Rule has specific ports but event doesn't - cannot confirm match
                        continue;
                    }
                    bool portMatch = rule.LocalPorts.Split(_separators, StringSplitOptions.RemoveEmptyEntries)
                        .Any(p => PortMatches(p.Trim(), pending.LocalPort));
                    if (!portMatch) continue;
                }

                // Conservative address matching
                // * addresses match all
                // Specific addresses must match (event address must be in rule's address list)
                // If rule has specific addresses but event value is empty, rule does NOT match
                if (!string.IsNullOrEmpty(rule.RemoteAddresses) && rule.RemoteAddresses != "*")
                {
                    if (string.IsNullOrEmpty(pending.RemoteAddress) || pending.RemoteAddress == "*")
                    {
                        // Rule has specific addresses but event doesn't - cannot confirm match
                        continue;
                    }
                    bool addressMatch = rule.RemoteAddresses.Split(_separators, StringSplitOptions.RemoveEmptyEntries)
                        .Any(a => AddressMatches(a.Trim(), pending.RemoteAddress));
                    if (!addressMatch) continue;
                }

                if (!string.IsNullOrEmpty(rule.LocalAddresses) && rule.LocalAddresses != "*")
                {
                    if (string.IsNullOrEmpty(pending.LocalAddress) || pending.LocalAddress == "*")
                    {
                        // Rule has specific addresses but event doesn't - cannot confirm match
                        continue;
                    }
                    bool addressMatch = rule.LocalAddresses.Split(_separators, StringSplitOptions.RemoveEmptyEntries)
                        .Any(a => AddressMatches(a.Trim(), pending.LocalAddress));
                    if (!addressMatch) continue;
                }

                // Conservative profile matching
                // "All" profiles matches all
                // Otherwise, rule must apply to current network profile
                if (rule.Profiles != "All")
                {
                    // For now, be conservative: if rule has specific profiles, we can't be certain it applies
                    // without knowing the current active profile. Return None to allow popup.
                    Debug.WriteLine($"[CheckMfwRuleStatus] Rule '{rule.Name}' has specific profiles '{rule.Profiles}' - cannot confirm match");
                    continue;
                }

                // All criteria matched
                if (rule.Status == "Allow")
                {
                    foundAllow = true;
                    Debug.WriteLine($"[CheckMfwRuleStatus] Conservative match found: Allow rule '{rule.Name}' covers event for {pending.AppPath}");
                }
                else if (rule.Status == "Block")
                {
                    foundBlock = true;
                    Debug.WriteLine($"[CheckMfwRuleStatus] Conservative match found: Block rule '{rule.Name}' covers event for {pending.AppPath}");
                }

                if (foundBlock) break;
            }

            if (foundBlock) return MfwRuleStatus.MfwBlock;
            if (foundAllow) return MfwRuleStatus.MfwAllow;

            Debug.WriteLine($"[CheckMfwRuleStatus] No conservative match found for {pending.AppPath} - returning None to allow popup");
            return MfwRuleStatus.None;
        }

        private static bool PortMatches(string rulePort, string eventPort)
        {
            // Use existing PortRange.TryParse for proper range support
            if (PortRange.TryParse(rulePort, out var portRange))
            {
                if (ushort.TryParse(eventPort, out var eventPortNum))
                {
                    return eventPortNum >= portRange.Begin && eventPortNum <= portRange.End;
                }
            }
            return false;
        }

        private static bool AddressMatches(string ruleAddress, string eventAddress)
        {
            // Use existing IPAddressRange.TryParse/Contains for proper CIDR/range support
            if (IPAddressRange.TryParse(ruleAddress, out var ipRange))
            {
                if (IPAddress.TryParse(eventAddress, out var eventIp))
                {
                    return ipRange.Contains(eventIp);
                }
            }
            return false;
        }

        public void ClearCaches()
        {
            _localCache.Remove(ServicesCacheKey);
            InvalidateRuleCache();
        }


        public static AdvancedRuleViewModel CreateAdvancedRuleViewModel(INetFwRule2 rule)
        {
            // Read COM properties once to avoid repeated interop calls
            var rawAppName = rule.ApplicationName;
            var rawProtocol = rule.Protocol;

            string appName = string.IsNullOrEmpty(rawAppName) ? string.Empty : rawAppName;
            string rawDescription = rule.Description ?? "N/A";
            string autoAllowedPublisher = string.Empty;
            if (rawDescription.StartsWith(MFWConstants.AutoAllowPublisherPrefix, StringComparison.OrdinalIgnoreCase))
            {
                int endIdx = rawDescription.IndexOf(']', MFWConstants.AutoAllowPublisherPrefix.Length);
                if (endIdx > 0)
                {
                    autoAllowedPublisher = rawDescription.Substring(MFWConstants.AutoAllowPublisherPrefix.Length, endIdx - MFWConstants.AutoAllowPublisherPrefix.Length);
                }
                rawDescription = string.Empty;
            }

            return new AdvancedRuleViewModel
            {
                Name = rule.Name ?? "Unnamed Rule",
                Description = rawDescription,
                IsEnabled = rule.Enabled,
                Status = rule.Action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW ? "Allow" : "Block",
                Direction = (Directions)rule.Direction,
                ApplicationName = appName == "*" ? "*" : PathResolver.NormalizePath(appName),
                LocalPorts = GetStr(rule.LocalPorts, "*"),
                RemotePorts = GetStr(rule.RemotePorts, "*"),
                Protocol = (int)rawProtocol,
                ProtocolName = GetProtocolName(rawProtocol),
                ServiceName = GetStr(rule.serviceName, string.Empty) == "*" ? string.Empty : GetStr(rule.serviceName, string.Empty),
                LocalAddresses = GetStr(rule.LocalAddresses, "*"),
                RemoteAddresses = GetStr(rule.RemoteAddresses, "*"),
                Profiles = GetProfileString(rule.Profiles),
                Grouping = rule.Grouping ?? string.Empty,
                InterfaceTypes = rule.InterfaceTypes ?? "All",
                IcmpTypesAndCodes = rule.IcmpTypesAndCodes ?? "",
                AutoAllowedPublisher = autoAllowedPublisher
            };
        }

        private static string GetProtocolName(int protocolValue)
        {
            return protocolValue switch
            {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMPv4",
                58 => "ICMPv6",
                2 => "IGMP",
                256 => "Any",
                _ => protocolValue.ToString(),
            };
        }


        private static string GetProfileString(int profiles)
        {
            if (profiles == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL) return "All";
            List<string> profileNames = [];
            if ((profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) != 0) profileNames.Add("Domain");
            if ((profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) != 0) profileNames.Add("Private");
            if ((profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) != 0) profileNames.Add("Public");
            return string.Join(", ", profileNames);
        }
    }
}