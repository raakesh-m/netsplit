// NetSplit: choose which internet connection Windows uses by default, and pin
// individual apps (Steam, ...) to another connection.
//
// How it works:
//  * Default connection = the adapter with the lowest interface metric. NetSplit
//    sets metrics with Set-NetIPInterface (needs admin, asked for via UAC).
//  * Pinned apps are started through ForceBindIP (tools\), which hooks the app's
//    socket calls and binds every connection to the chosen adapter. This is the same
//    trick Plexo uses (localAddress per connection), applied to apps we don't own.
//  * If only the non-default adapter has IPv6, IPv6 traffic would still leak onto it,
//    so NetSplit turns IPv6 off on that adapter (and back on when you reset).

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace NetSplit
{
    public class Rule
    {
        public string Name { get; set; }
        public string ExePath { get; set; }
        public string Args { get; set; }
        public string NetworkGuid { get; set; }
        public string NetworkDesc { get; set; }
        public string NetworkLabel { get; set; }
        public bool DelayInject { get; set; }
        public bool LaunchAtStartup { get; set; }
        public int LastPid { get; set; }
        public long LastStartTicks { get; set; }
    }

    public class Config
    {
        public List<Rule> Rules { get; set; }
        public List<string> Ipv6DisabledAdapters { get; set; }
        public bool TrayHintShown { get; set; }
        public Config() { Rules = new List<Rule>(); Ipv6DisabledAdapters = new List<string>(); }
    }

    public class NetInfo
    {
        public string Guid, Name, Desc, Kind, Gateway;
        public int Index, IfMetric, RouteMetric;
        public bool AutoMetric, HasV6Default, V6Off;
        public long LinkSpeed;
        public IPAddress Ip;
        public HashSet<IPAddress> AllIps = new HashSet<IPAddress>();
        public NetworkInterface Nic;
        public int Effective { get { return IfMetric + RouteMetric; } }
        public string Label { get { return Kind == Name ? Kind : Kind + " (" + Name + ")"; } }
    }

    public class RuleView
    {
        public Rule Rule;
        public string NetText, Text;
        public int Level; // 0 neutral, 1 good, 2 warning
    }

    public static class Core
    {
        public static readonly string AppDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        public static readonly string ToolsDir = Path.Combine(AppDir, "tools");
        static readonly string ConfigPath = Path.Combine(AppDir, "netsplit.json");

        // ---------- config ----------

        public static Config LoadConfig()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var c = new JavaScriptSerializer().Deserialize<Config>(File.ReadAllText(ConfigPath));
                    if (c != null)
                    {
                        if (c.Rules == null) c.Rules = new List<Rule>();
                        if (c.Ipv6DisabledAdapters == null) c.Ipv6DisabledAdapters = new List<string>();
                        return c;
                    }
                }
            }
            catch { }
            return null;
        }

        public static void SaveConfig(Config c)
        {
            lock (c)
            {
                string tmp = ConfigPath + ".tmp";
                File.WriteAllText(tmp, new JavaScriptSerializer().Serialize(c));
                if (File.Exists(ConfigPath)) File.Delete(ConfigPath);
                File.Move(tmp, ConfigPath);
            }
        }

        // ---------- network discovery ----------

        static IEnumerable<ManagementObject> Query(string wql)
        {
            using (var s = new ManagementObjectSearcher(@"root\StandardCimv2", wql))
                foreach (ManagementObject o in s.Get()) yield return o;
        }

        static string KindOf(NetworkInterface nic)
        {
            string d = (nic.Description + " " + nic.Name).ToLowerInvariant();
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) return "Wi-Fi";
            if (d.Contains("ndis") || d.Contains("android") || d.Contains("iphone") || d.Contains("apple mobile") ||
                d.Contains("tether") || d.Contains("modem") || d.Contains("mobile broadband")) return "Phone USB tether";
            if (d.Contains("vpn") || d.Contains("virtual") || d.Contains("tap-") || d.Contains("wireguard") ||
                d.Contains("hyper-v") || d.Contains("tunnel")) return "Virtual / VPN";
            return "Ethernet";
        }

        /// <summary>Connected adapters that have a route to the internet (a default gateway).</summary>
        public static List<NetInfo> Scan()
        {
            var ifMetric = new Dictionary<int, int>();
            var ifAuto = new Dictionary<int, bool>();
            var route4 = new Dictionary<int, int>();
            var route6 = new HashSet<int>();
            var v6Off = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var o in Query("SELECT InterfaceIndex,InterfaceMetric,AutomaticMetric FROM MSFT_NetIPInterface WHERE AddressFamily=2"))
                {
                    int i = Convert.ToInt32(o["InterfaceIndex"]);
                    ifMetric[i] = Convert.ToInt32(o["InterfaceMetric"]);
                    ifAuto[i] = Convert.ToInt32(o["AutomaticMetric"]) == 1;
                }
                foreach (var o in Query("SELECT InterfaceIndex,RouteMetric,DestinationPrefix FROM MSFT_NetRoute WHERE DestinationPrefix='0.0.0.0/0' OR DestinationPrefix='::/0'"))
                {
                    int i = Convert.ToInt32(o["InterfaceIndex"]);
                    if ((string)o["DestinationPrefix"] == "::/0") { route6.Add(i); continue; }
                    int m = Convert.ToInt32(o["RouteMetric"]);
                    int prev;
                    if (!route4.TryGetValue(i, out prev) || m < prev) route4[i] = m;
                }
                foreach (var o in Query("SELECT Name,Enabled FROM MSFT_NetAdapterBindingSettingData WHERE ComponentID='ms_tcpip6'"))
                    if (!(bool)o["Enabled"]) v6Off.Add((string)o["Name"]);
            }
            catch { }

            var list = new List<NetInfo>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                IPInterfaceProperties p;
                IPv4InterfaceProperties p4;
                try { p = nic.GetIPProperties(); p4 = p.GetIPv4Properties(); }
                catch { continue; }
                if (p4 == null) continue;

                IPAddress ip = null;
                foreach (var ua in p.UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !ua.Address.ToString().StartsWith("169.254."))
                    { ip = ua.Address; break; }
                if (ip == null) continue;

                string gw = null;
                foreach (var g in p.GatewayAddresses)
                    if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                    { gw = g.Address.ToString(); break; }
                if (gw == null && !route4.ContainsKey(p4.Index)) continue;

                int metric, rm;
                bool auto;
                var all = new HashSet<IPAddress>(p.UnicastAddresses.Select(ua => new IPAddress(ua.Address.GetAddressBytes())));
                list.Add(new NetInfo
                {
                    Guid = nic.Id,
                    Name = nic.Name,
                    Desc = nic.Description,
                    Kind = KindOf(nic),
                    Gateway = gw,
                    Index = p4.Index,
                    IfMetric = ifMetric.TryGetValue(p4.Index, out metric) ? metric : 0,
                    AutoMetric = ifAuto.TryGetValue(p4.Index, out auto) && auto,
                    RouteMetric = route4.TryGetValue(p4.Index, out rm) ? rm : 0,
                    HasV6Default = route6.Contains(p4.Index),
                    V6Off = v6Off.Contains(nic.Name),
                    LinkSpeed = nic.Speed,
                    Ip = ip,
                    AllIps = all,
                    Nic = nic
                });
            }
            return list.OrderBy(n => n.Effective).ToList();
        }

        public static NetInfo DefaultOf(List<NetInfo> nets)
        {
            return nets.Where(n => n.Kind != "Virtual / VPN").OrderBy(n => n.Effective).FirstOrDefault()
                ?? nets.FirstOrDefault();
        }

        /// <summary>TCP handshake to a public server from this adapter's address. Milliseconds, or -1.</summary>
        public static int Probe(IPAddress local)
        {
            foreach (var target in new[] { "1.1.1.1", "8.8.8.8" })
            {
                try
                {
                    using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        s.Bind(new IPEndPoint(local, 0));
                        var sw = Stopwatch.StartNew();
                        var ar = s.BeginConnect(new IPEndPoint(IPAddress.Parse(target), 443), null, null);
                        if (ar.AsyncWaitHandle.WaitOne(3000))
                        {
                            s.EndConnect(ar);
                            return (int)sw.ElapsedMilliseconds;
                        }
                    }
                }
                catch { }
            }
            return -1;
        }

        // ---------- which app uses which network ----------

        [DllImport("iphlpapi.dll")]
        static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

        /// <summary>Established TCP connections (IPv4 and IPv6, non-loopback): owning PID and local address.</summary>
        public static List<KeyValuePair<int, IPAddress>> TcpConnections()
        {
            var res = new List<KeyValuePair<int, IPAddress>>();
            ReadTcpTable(2, res);
            ReadTcpTable(23, res);
            return res;
        }

        static void ReadTcpTable(int af, List<KeyValuePair<int, IPAddress>> res)
        {
            bool v6 = af == 23;
            int rowSize = v6 ? 56 : 24;
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5, 0);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                size += 4096;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    uint rc = GetExtendedTcpTable(buf, ref size, false, af, 5, 0);
                    if (rc == 122) continue; // buffer too small, size updated
                    if (rc != 0) return;
                    int n = Marshal.ReadInt32(buf);
                    IntPtr row = buf + 4;
                    for (int i = 0; i < n; i++, row += rowSize)
                    {
                        if (Marshal.ReadInt32(row, v6 ? 48 : 0) != 5) continue; // ESTABLISHED
                        IPAddress local, remote;
                        if (v6)
                        {
                            var b = new byte[16];
                            Marshal.Copy(row, b, 0, 16);
                            local = new IPAddress(b);
                            b = new byte[16];
                            Marshal.Copy(row + 24, b, 0, 16);
                            remote = new IPAddress(b);
                        }
                        else
                        {
                            local = new IPAddress((long)(uint)Marshal.ReadInt32(row, 4));
                            remote = new IPAddress((long)(uint)Marshal.ReadInt32(row, 12));
                        }
                        if (IPAddress.IsLoopback(local) || IPAddress.IsLoopback(remote)) continue;
                        res.Add(new KeyValuePair<int, IPAddress>(Marshal.ReadInt32(row, v6 ? 52 : 20), local));
                    }
                    return;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }

        // ---------- re-pinning apps that restart themselves ----------

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32
        {
            public uint dwSize, cntUsage, th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID, cntThreads, th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, UIntPtr size, uint type, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, UIntPtr size, uint type);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr written);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, UIntPtr stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll")] static extern bool GetExitCodeThread(IntPtr h, out uint code);
        [DllImport("kernel32.dll")] static extern bool IsWow64Process(IntPtr h, out bool wow);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr mod, string name);

        /// <summary>Parent process ID of every running process.</summary>
        public static Dictionary<int, int> ParentPids()
        {
            var map = new Dictionary<int, int>();
            IntPtr snap = CreateToolhelp32Snapshot(2, 0);
            if (snap == new IntPtr(-1)) return map;
            try
            {
                var e = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                if (Process32FirstW(snap, ref e))
                    do { map[(int)e.th32ProcessID] = (int)e.th32ParentProcessID; } while (Process32NextW(snap, ref e));
            }
            finally { CloseHandle(snap); }
            return map;
        }

        /// <summary>
        /// Loads BindIP64.dll into a running 64-bit process. The process must have been started by a
        /// pinned process, so it inherited the FORCEDIP variable that tells BindIP which network to use.
        /// </summary>
        public static bool InjectBindIp(int pid)
        {
            if (IntPtr.Size != 8) return false;
            string dll = Path.Combine(ToolsDir, "BindIP64.dll");
            if (!File.Exists(dll)) return false;
            IntPtr h = OpenProcess(0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400 | 0x00100000, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                bool wow;
                if (IsWow64Process(h, out wow) && wow) return false; // 32-bit target
                byte[] path = Encoding.Unicode.GetBytes(dll + "\0");
                IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, (UIntPtr)path.Length, 0x3000, 0x04);
                if (mem == IntPtr.Zero) return false;
                try
                {
                    UIntPtr written;
                    if (!WriteProcessMemory(h, mem, path, (UIntPtr)path.Length, out written)) return false;
                    IntPtr loadLibrary = GetProcAddress(GetModuleHandleW("kernel32.dll"), "LoadLibraryW");
                    IntPtr thread = CreateRemoteThread(h, IntPtr.Zero, UIntPtr.Zero, loadLibrary, mem, 0, IntPtr.Zero);
                    if (thread == IntPtr.Zero) return false;
                    try
                    {
                        WaitForSingleObject(thread, 10000);
                        uint code;
                        return GetExitCodeThread(thread, out code) && code != 0;
                    }
                    finally { CloseHandle(thread); }
                }
                finally { VirtualFreeEx(h, mem, UIntPtr.Zero, 0x8000); }
            }
            finally { CloseHandle(h); }
        }

        static readonly HashSet<int> pinnedPids = new HashSet<int>();

        /// <summary>
        /// Apps like Steam sometimes restart themselves (after an update), and the new copy isn't pinned.
        /// Finds such copies (a child of a pinned copy) and pins them too. Returns the names of re-pinned apps.
        /// </summary>
        public static List<string> RepinChildren(Config cfg)
        {
            var repinned = new List<string>();
            List<Rule> rules;
            lock (cfg) rules = cfg.Rules.ToList();
            Dictionary<int, int> parents = null;
            foreach (var r in rules)
            {
                var procs = RunningCopies(r);
                try
                {
                    if (procs.Length == 0) continue;
                    foreach (var p in procs) if (IsOurs(r, p)) pinnedPids.Add(p.Id);
                    foreach (var p in procs)
                    {
                        if (pinnedPids.Contains(p.Id)) continue;
                        if (parents == null) parents = ParentPids();
                        int parent;
                        if (!parents.TryGetValue(p.Id, out parent) || !pinnedPids.Contains(parent)) continue;
                        if (!InjectBindIp(p.Id)) continue;
                        pinnedPids.Add(p.Id);
                        lock (cfg)
                        {
                            r.LastPid = p.Id;
                            try { r.LastStartTicks = p.StartTime.ToUniversalTime().Ticks; } catch { }
                        }
                        try { SaveConfig(cfg); } catch { }
                        repinned.Add(r.Name);
                    }
                }
                finally { foreach (var p in procs) p.Dispose(); }
            }
            return repinned;
        }

        public static NetInfo Resolve(Rule r, List<NetInfo> nets)
        {
            return nets.FirstOrDefault(n => string.Equals(n.Guid, r.NetworkGuid, StringComparison.OrdinalIgnoreCase))
                ?? nets.FirstOrDefault(n => n.Desc == r.NetworkDesc);
        }

        public static Process[] RunningCopies(Rule r)
        {
            return Process.GetProcessesByName(Path.GetFileNameWithoutExtension(r.ExePath));
        }

        public static bool IsOurs(Rule r, Process p)
        {
            try { return p.Id == r.LastPid && p.StartTime.ToUniversalTime().Ticks == r.LastStartTicks; }
            catch { return false; }
        }

        public static RuleView Status(Rule r, List<NetInfo> nets, List<KeyValuePair<int, IPAddress>> conns, bool agent)
        {
            var v = new RuleView { Rule = r };
            var net = Resolve(r, nets);
            v.NetText = net != null ? net.Label : r.NetworkLabel + " (not connected)";
            var procs = RunningCopies(r);
            try
            {
                if (procs.Length == 0) { v.Text = "Not running"; return v; }
                var pids = new HashSet<int>(procs.Select(p => p.Id));
                bool ours = procs.Any(p => IsOurs(r, p));
                int on = 0;
                var off = new Dictionary<string, int>();
                foreach (var c in conns)
                {
                    if (!pids.Contains(c.Key)) continue;
                    if (net != null && net.AllIps.Contains(c.Value)) { on++; continue; }
                    var other = nets.FirstOrDefault(n => n.AllIps.Contains(c.Value));
                    string name = other != null ? other.Label : c.Value.ToString();
                    int k;
                    off[name] = (off.TryGetValue(name, out k) ? k : 0) + 1;
                }
                if (net == null)
                { v.Text = "⚠ Running, but " + r.NetworkLabel + " is disconnected"; v.Level = 2; }
                else if (off.Count > 0 && agent)
                { v.Text = string.Format("↻ Moving {0} connection(s) from {1} to {2}…", off.Values.Sum(), string.Join(", ", off.Keys), net.Label); v.Level = 0; }
                else if (off.Count > 0)
                { v.Text = string.Format("⚠ NOT pinned: {0} connection(s) on {1}. Turn on the pinning service.", off.Values.Sum(), string.Join(", ", off.Keys)); v.Level = 2; }
                else if (on > 0)
                { v.Text = string.Format("✔ Pinned: {0} connection(s), all on {1}", on, net.Label); v.Level = 1; }
                else if (agent || ours)
                { v.Text = "✔ Pinned (no traffic right now)"; v.Level = 1; }
                else
                { v.Text = "⚠ The pinning service is off, so it will use the default connection"; v.Level = 2; }
                return v;
            }
            finally { foreach (var p in procs) p.Dispose(); }
        }

        // ---------- launching pinned apps ----------

        static bool Is64(string exe)
        {
            using (var fs = File.OpenRead(exe))
            using (var br = new BinaryReader(fs))
            {
                fs.Seek(0x3C, SeekOrigin.Begin);
                int pe = br.ReadInt32();
                fs.Seek(pe + 4, SeekOrigin.Begin);
                ushort m = br.ReadUInt16();
                return m == 0x8664 || m == 0xAA64;
            }
        }

        static bool WaitGone(Rule r, int ms)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < ms)
            {
                var ps = RunningCopies(r);
                bool any = ps.Length > 0;
                foreach (var p in ps) p.Dispose();
                if (!any) return true;
                Thread.Sleep(500);
            }
            return false;
        }

        static string CloseApp(Rule r, Func<string, bool> ask)
        {
            if (Path.GetFileName(r.ExePath).Equals("steam.exe", StringComparison.OrdinalIgnoreCase))
            {
                try { Process.Start(new ProcessStartInfo(r.ExePath, "-shutdown") { UseShellExecute = false }).Dispose(); }
                catch { }
            }
            else
            {
                foreach (var p in RunningCopies(r)) { try { p.CloseMainWindow(); } catch { } p.Dispose(); }
            }
            if (WaitGone(r, 45000)) return null;
            if (!ask(r.Name + " didn't close by itself. Force it to close? Anything unsaved in it would be lost.")) return "";
            foreach (var p in RunningCopies(r)) { try { p.Kill(); } catch { } p.Dispose(); }
            return WaitGone(r, 10000) ? null : "Couldn't close " + r.Name + ".";
        }

        /// <summary>Starts the rule's app pinned to its network. null = success, "" = cancelled, otherwise an error.</summary>
        public static string Launch(Rule r, Config cfg, Func<string, bool> ask)
        {
            if (!File.Exists(r.ExePath)) return "Can't find " + r.ExePath;
            var net = Resolve(r, Scan());
            if (net == null) return r.NetworkLabel + " isn't connected right now. Connect it and try again.";

            var running = RunningCopies(r);
            bool ours = running.Any(p => IsOurs(r, p));
            int count = running.Length;
            foreach (var p in running) p.Dispose();
            if (count > 0)
            {
                string q = ours
                    ? string.Format("{0} is already running pinned to {1}.\n\nRestart it anyway?", r.Name, net.Label)
                    : string.Format("{0} is already running, but it wasn't started by NetSplit, so it's using the default connection.\n\nClose it and restart it on {1}?", r.Name, net.Label);
                if (!ask(q)) return "";
                string err = CloseApp(r, ask);
                if (err != null) return err;
                Thread.Sleep(1500);
            }

            string loader = Path.Combine(ToolsDir, Is64(r.ExePath) ? "ForceBindIP64.exe" : "ForceBindIP.exe");
            string appArgs = string.IsNullOrWhiteSpace(r.Args) ? "" : r.Args.Trim();
            bool direct = !File.Exists(loader);
            // Without ForceBindIP (optional, see tools\get-forcebindip.ps1) the app starts normally and
            // the pinning service moves its connections.
            string args = direct ? appArgs
                : (r.DelayInject ? "-i " : "") + net.Guid + " \"" + r.ExePath + "\"" + (appArgs == "" ? "" : " " + appArgs);
            DateTime started = DateTime.Now.AddSeconds(-2);
            int exit;
            using (var p = Process.Start(new ProcessStartInfo(direct ? r.ExePath : loader, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(r.ExePath)
            }))
            {
                if (direct) exit = 0;
                else
                {
                    if (!p.WaitForExit(60000)) return "ForceBindIP took too long to start " + r.Name + ".";
                    exit = p.ExitCode;
                }
            }

            // Find the process ForceBindIP created so we can tell later that it is pinned.
            for (int i = 0; i < 20; i++)
            {
                Process newest = null;
                foreach (var p in RunningCopies(r))
                {
                    try
                    {
                        if (p.StartTime >= started && (newest == null || p.StartTime > newest.StartTime)) { if (newest != null) newest.Dispose(); newest = p; continue; }
                    }
                    catch { }
                    p.Dispose();
                }
                if (newest != null)
                {
                    lock (cfg)
                    {
                        r.LastPid = newest.Id;
                        r.LastStartTicks = newest.StartTime.ToUniversalTime().Ticks;
                    }
                    newest.Dispose();
                    SaveConfig(cfg);
                    return null;
                }
                Thread.Sleep(500);
            }
            return string.Format("{0} didn't start (ForceBindIP exit code {1}). Try editing the app and ticking “Delayed injection”.", r.Name, exit);
        }

        // ---------- changing the default connection (admin) ----------

        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        static string Q(string s) { return "'" + s.Replace("'", "''") + "'"; }

        /// <summary>Runs PowerShell as administrator (UAC prompt if needed). null = success, otherwise an error.</summary>
        public static string RunAdminPs(IEnumerable<string> commands)
        {
            string errFile = Path.Combine(Path.GetTempPath(), "netsplit-error.txt");
            try { File.Delete(errFile); } catch { }
            string script = "$ErrorActionPreference='Stop'; try { " + string.Join("; ", commands) +
                            "; exit 0 } catch { $_ | Out-File -LiteralPath " + Q(errFile) + "; exit 1 }";
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            if (IsAdmin()) { psi.UseShellExecute = false; psi.CreateNoWindow = true; }
            else { psi.UseShellExecute = true; psi.Verb = "runas"; psi.WindowStyle = ProcessWindowStyle.Hidden; }
            try
            {
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit(60000);
                    if (p.ExitCode == 0) return null;
                }
            }
            catch (Win32Exception) { return "Windows needs administrator permission to change the default connection, and it wasn't given."; }
            try { return File.ReadAllText(errFile).Trim(); } catch { return "The change didn't go through."; }
        }

        public static string MakeDefault(NetInfo chosen, List<NetInfo> nets, Config cfg)
        {
            var cmds = new List<string>();
            var enable = new List<string>();
            var disable = new List<string>();
            cmds.Add(string.Format("Set-NetIPInterface -InterfaceIndex {0} -InterfaceMetric 10", chosen.Index));
            int m = 50;
            foreach (var n in nets.Where(n => n != chosen))
            {
                cmds.Add(string.Format("Set-NetIPInterface -InterfaceIndex {0} -InterfaceMetric {1}", n.Index, m));
                m += 10;
            }
            List<string> ours;
            lock (cfg) ours = cfg.Ipv6DisabledAdapters.ToList();
            bool chosenWasOurs = ours.Contains(chosen.Name);
            if (chosen.HasV6Default || chosenWasOurs)
            {
                // The default has IPv6 (or will again): undo anything we switched off.
                enable.AddRange(ours);
            }
            else
            {
                // IPv6 would bypass the default and leak onto the other adapters.
                disable.AddRange(nets.Where(n => n != chosen && n.HasV6Default && !n.V6Off).Select(n => n.Name));
            }
            foreach (var a in enable) cmds.Add("Enable-NetAdapterBinding -Name " + Q(a) + " -ComponentID ms_tcpip6");
            foreach (var a in disable) cmds.Add("Disable-NetAdapterBinding -Name " + Q(a) + " -ComponentID ms_tcpip6");

            string err = RunAdminPs(cmds);
            if (err != null) return err;
            lock (cfg)
            {
                foreach (var a in enable) cfg.Ipv6DisabledAdapters.Remove(a);
                foreach (var a in disable) if (!cfg.Ipv6DisabledAdapters.Contains(a)) cfg.Ipv6DisabledAdapters.Add(a);
            }
            SaveConfig(cfg);
            return null;
        }

        public static string ResetToAutomatic(List<NetInfo> nets, Config cfg)
        {
            var cmds = new List<string>();
            foreach (var n in nets) cmds.Add(string.Format("Set-NetIPInterface -InterfaceIndex {0} -AutomaticMetric Enabled", n.Index));
            List<string> ours;
            lock (cfg) ours = cfg.Ipv6DisabledAdapters.ToList();
            foreach (var a in ours) cmds.Add("Enable-NetAdapterBinding -Name " + Q(a) + " -ComponentID ms_tcpip6");
            if (cmds.Count == 0) return null;
            string err = RunAdminPs(cmds);
            if (err != null) return err;
            lock (cfg) cfg.Ipv6DisabledAdapters.Clear();
            SaveConfig(cfg);
            return null;
        }

        // ---------- Windows integration ----------

        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

        public static bool StartsWithWindows
        {
            get
            {
                using (var k = Registry.CurrentUser.OpenSubKey(RunKey))
                    return k != null && k.GetValue("NetSplit") != null;
            }
            set
            {
                using (var k = Registry.CurrentUser.CreateSubKey(RunKey))
                {
                    if (value) k.SetValue("NetSplit", "\"" + Application.ExecutablePath + "\" --tray");
                    else k.DeleteValue("NetSplit", false);
                }
            }
        }

        public static string CreateShortcut(Rule r, string netLabel)
        {
            string name = string.Format("{0} (on {1})", r.Name, netLabel);
            foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '-');
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), name + ".lnk");
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(t);
            object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { path });
            Type lt = lnk.GetType();
            lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { Application.ExecutablePath });
            lt.InvokeMember("Arguments", BindingFlags.SetProperty, null, lnk, new object[] { "--launch \"" + r.Name + "\"" });
            lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { AppDir });
            lt.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { r.ExePath + ",0" });
            lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { "Start " + r.Name + " pinned to " + netLabel + " (NetSplit)" });
            lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
            Marshal.FinalReleaseComObject(lnk);
            Marshal.FinalReleaseComObject(shell);
            return path;
        }

        public static string FormatRate(double bps)
        {
            if (bps < 1024) return "0 KB/s";
            if (bps < 1024 * 1024) return (bps / 1024).ToString("0") + " KB/s";
            return (bps / 1024 / 1024).ToString("0.0") + " MB/s";
        }

        // ---------- icon ----------

        public static Bitmap DrawIcon(int s)
        {
            var b = new Bitmap(s, s, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(b))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float k = s / 32f;
                using (var path = new GraphicsPath())
                {
                    float x = 1 * k, y = 1 * k, w = 30 * k, rr = 7 * k * 2;
                    path.AddArc(x, y, rr, rr, 180, 90);
                    path.AddArc(x + w - rr, y, rr, rr, 270, 90);
                    path.AddArc(x + w - rr, y + w - rr, rr, rr, 0, 90);
                    path.AddArc(x, y + w - rr, rr, rr, 90, 90);
                    path.CloseFigure();
                    using (var br = new LinearGradientBrush(new PointF(0, 0), new PointF(0, s), Color.FromArgb(37, 99, 235), Color.FromArgb(30, 58, 138)))
                        g.FillPath(br, path);
                }
                Func<Color, Pen> pen = c => new Pen(c, Math.Max(1.6f, 3.2f * k)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
                using (var p = pen(Color.FromArgb(74, 222, 128)))
                    g.DrawBezier(p, 14 * k, 16 * k, 19 * k, 16 * k, 19 * k, 9 * k, 25 * k, 9 * k);
                using (var p = pen(Color.FromArgb(251, 191, 36)))
                    g.DrawBezier(p, 14 * k, 16 * k, 19 * k, 16 * k, 19 * k, 23 * k, 25 * k, 23 * k);
                using (var p = pen(Color.White))
                    g.DrawLine(p, 7 * k, 16 * k, 14 * k, 16 * k);
            }
            return b;
        }

        public static void WriteIco(string path)
        {
            int[] sizes = { 16, 20, 24, 32, 40, 48, 64, 256 };
            var pngs = sizes.Select(s =>
            {
                using (var b = DrawIcon(s))
                using (var ms = new MemoryStream()) { b.Save(ms, ImageFormat.Png); return ms.ToArray(); }
            }).ToList();
            using (var bw = new BinaryWriter(File.Create(path)))
            {
                bw.Write((short)0); bw.Write((short)1); bw.Write((short)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    byte d = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
                    bw.Write(d); bw.Write(d); bw.Write((byte)0); bw.Write((byte)0);
                    bw.Write((short)1); bw.Write((short)32);
                    bw.Write(pngs[i].Length); bw.Write(offset);
                    offset += pngs[i].Length;
                }
                foreach (var png in pngs) bw.Write(png);
            }
        }
    }

    // ===================================================================== pinning service
    //
    // ForceBindIP only catches some of the ways an app opens connections (Steam's downloads slip
    // past it). The service works at the routing level instead: it watches the pinned apps'
    // connections, adds a host route through the pinned network for every server they talk to,
    // and resets connections that already went out the wrong way so they reconnect correctly.
    // Runs elevated (scheduled task "NetSplit Agent").

    public static class Agent
    {
        public const string MutexName = "NetSplit.Agent";
        public const string TaskName = "NetSplit Agent";
        static readonly string RoutesFile = Path.Combine(Core.AppDir, "agent-routes.txt");

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest, dwForwardMask, dwForwardPolicy, dwForwardNextHop;
            public int dwForwardIfIndex;
            public uint dwForwardType, dwForwardProto, dwForwardAge, dwForwardNextHopAS;
            public int dwForwardMetric1, dwForwardMetric2, dwForwardMetric3, dwForwardMetric4, dwForwardMetric5;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW
        {
            public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort;
        }

        [DllImport("iphlpapi.dll")] static extern int CreateIpForwardEntry(ref MIB_IPFORWARDROW r);
        [DllImport("iphlpapi.dll")] static extern int DeleteIpForwardEntry(ref MIB_IPFORWARDROW r);
        [DllImport("iphlpapi.dll")] static extern int SetTcpEntry(ref MIB_TCPROW r);
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

        class Conn { public uint State, Local, LocalPort, Remote, RemotePort; public int Pid; }

        class HostRoute { public uint Dest, NextHop; public int IfIndex, Metric; public DateTime LastUsed; }

        public static bool IsRunning()
        {
            try { Mutex.OpenExisting(MutexName).Dispose(); return true; }
            catch (UnauthorizedAccessException) { return true; } // exists, owned by the elevated service
            catch { return false; }
        }

        static uint ToUint(IPAddress ip) { return BitConverter.ToUInt32(ip.GetAddressBytes(), 0); }
        static IPAddress ToIp(uint a) { return new IPAddress((long)a); }

        static bool IsPublic(uint a)
        {
            byte[] b = BitConverter.GetBytes(a);
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            return true;
        }

        static List<Conn> TcpRows()
        {
            var res = new List<Conn>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                size += 4096;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    uint rc = GetExtendedTcpTable(buf, ref size, false, 2, 5, 0);
                    if (rc == 122) continue;
                    if (rc != 0) return res;
                    int n = Marshal.ReadInt32(buf);
                    IntPtr row = buf + 4;
                    for (int i = 0; i < n; i++, row += 24)
                    {
                        uint state = (uint)Marshal.ReadInt32(row, 0);
                        if (state != 3 && state != 5) continue; // SYN_SENT or ESTABLISHED
                        res.Add(new Conn
                        {
                            State = state,
                            Local = (uint)Marshal.ReadInt32(row, 4),
                            LocalPort = (uint)Marshal.ReadInt32(row, 8),
                            Remote = (uint)Marshal.ReadInt32(row, 12),
                            RemotePort = (uint)Marshal.ReadInt32(row, 16),
                            Pid = Marshal.ReadInt32(row, 20)
                        });
                    }
                    return res;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return res;
        }

        static MIB_IPFORWARDROW Row(HostRoute r)
        {
            return new MIB_IPFORWARDROW
            {
                dwForwardDest = r.Dest,
                dwForwardMask = 0xFFFFFFFF,
                dwForwardNextHop = r.NextHop,
                dwForwardIfIndex = r.IfIndex,
                dwForwardType = 4,  // indirect (via a gateway)
                dwForwardProto = 3, // static, non-persistent: gone after a reboot
                dwForwardMetric1 = r.Metric,
                dwForwardMetric2 = -1, dwForwardMetric3 = -1, dwForwardMetric4 = -1, dwForwardMetric5 = -1
            };
        }

        static bool AddRoute(HostRoute r)
        {
            var row = Row(r);
            int rc = CreateIpForwardEntry(ref row);
            return rc == 0 || rc == 5010; // 5010 = already exists
        }

        static void DeleteRoute(HostRoute r)
        {
            var row = Row(r);
            DeleteIpForwardEntry(ref row);
        }

        static void KillConnection(Conn c)
        {
            var row = new MIB_TCPROW { dwState = 12, dwLocalAddr = c.Local, dwLocalPort = c.LocalPort, dwRemoteAddr = c.Remote, dwRemotePort = c.RemotePort };
            SetTcpEntry(ref row); // 12 = DELETE_TCB: resets the connection, the app reconnects
        }

        static void SaveRoutes(Dictionary<uint, HostRoute> routes)
        {
            try
            {
                File.WriteAllLines(RoutesFile, routes.Values.Select(r =>
                    string.Join(" ", ToIp(r.Dest), ToIp(r.NextHop), r.IfIndex, r.Metric)).ToArray());
            }
            catch { }
        }

        /// <summary>Removes routes left behind by a previous run that didn't exit cleanly.</summary>
        static void CleanupStale()
        {
            try
            {
                if (!File.Exists(RoutesFile)) return;
                foreach (var line in File.ReadAllLines(RoutesFile))
                {
                    var p = line.Split(' ');
                    if (p.Length != 4) continue;
                    DeleteRoute(new HostRoute { Dest = ToUint(IPAddress.Parse(p[0])), NextHop = ToUint(IPAddress.Parse(p[1])), IfIndex = int.Parse(p[2]), Metric = int.Parse(p[3]) });
                }
                File.Delete(RoutesFile);
            }
            catch { }
        }

        public static int Run()
        {
            bool created;
            using (var mutex = new Mutex(true, MutexName, out created))
            {
                if (!created) return 0;
                CleanupStale();
                var routes = new Dictionary<uint, HostRoute>();
                Config cfg = new Config();
                DateTime cfgTime = DateTime.MinValue, lastScan = DateTime.MinValue;
                List<NetInfo> nets = new List<NetInfo>();
                bool netChanged = true;
                NetworkChange.NetworkAddressChanged += delegate { netChanged = true; };
                string cfgPath = Path.Combine(Core.AppDir, "netsplit.json");
                var logPath = Path.Combine(Core.AppDir, "agent.log");
                Action<string> log = s => { try { File.AppendAllText(logPath, DateTime.Now.ToString("MM-dd HH:mm:ss ") + s + "\r\n"); } catch { } };
                try { if (File.Exists(logPath) && new FileInfo(logPath).Length > 1000000) File.Delete(logPath); } catch { }
                log("service started");

                while (true)
                {
                    try
                    {
                        var now = DateTime.UtcNow;
                        DateTime mt = File.Exists(cfgPath) ? File.GetLastWriteTimeUtc(cfgPath) : DateTime.MinValue;
                        if (mt != cfgTime) { cfg = Core.LoadConfig() ?? new Config(); cfgTime = mt; }
                        if (netChanged || (now - lastScan).TotalSeconds >= 10) { netChanged = false; nets = Core.Scan(); lastScan = now; }

                        var rows = TcpRows();
                        bool changed = false;
                        var validTargets = new HashSet<string>();

                        foreach (var rule in cfg.Rules)
                        {
                            var net = Core.Resolve(rule, nets);
                            if (net == null || net.Gateway == null) continue;
                            uint gw = ToUint(IPAddress.Parse(net.Gateway));
                            uint localIp = ToUint(net.Ip);
                            validTargets.Add(gw + "/" + net.Index);

                            var pids = new HashSet<int>();
                            foreach (var p in Core.RunningCopies(rule)) { pids.Add(p.Id); p.Dispose(); }
                            if (pids.Count == 0) continue;

                            foreach (var c in rows)
                            {
                                if (!pids.Contains(c.Pid) || !IsPublic(c.Remote)) continue;
                                HostRoute hr;
                                if (routes.TryGetValue(c.Remote, out hr) && (hr.NextHop != gw || hr.IfIndex != net.Index))
                                {
                                    DeleteRoute(hr); routes.Remove(c.Remote); hr = null; changed = true;
                                }
                                if (hr == null)
                                {
                                    hr = new HostRoute { Dest = c.Remote, NextHop = gw, IfIndex = net.Index, Metric = Math.Max(1, net.IfMetric) + 1 };
                                    if (!AddRoute(hr)) { log("couldn't add route for " + ToIp(c.Remote)); continue; }
                                    routes[c.Remote] = hr;
                                    changed = true;
                                    log(string.Format("{0}: {1} -> {2}", rule.Name, ToIp(c.Remote), net.Label));
                                }
                                hr.LastUsed = now;
                                if (c.Local != localIp) KillConnection(c); // went out the wrong way; it reconnects through the route
                            }
                        }

                        // Drop routes nobody has used for 15 minutes, or whose network went away / changed.
                        foreach (var hr in routes.Values.ToList())
                        {
                            bool stale = (now - hr.LastUsed).TotalMinutes > 15 || !validTargets.Contains(hr.NextHop + "/" + hr.IfIndex);
                            if (!stale) continue;
                            DeleteRoute(hr);
                            routes.Remove(hr.Dest);
                            changed = true;
                        }
                        if (changed) SaveRoutes(routes);
                    }
                    catch (Exception ex) { log("error: " + ex.Message); }
                    Thread.Sleep(500);
                }
            }
        }

        /// <summary>Registers the service to start at logon (elevated) and starts it now. Asks for admin once.</summary>
        public static string Install()
        {
            string user = WindowsIdentity.GetCurrent().Name;
            Func<string, string> q = s => "'" + s.Replace("'", "''") + "'";
            return Core.RunAdminPs(new[]
            {
                "$a = New-ScheduledTaskAction -Execute " + q(Application.ExecutablePath) + " -Argument '--agent' -WorkingDirectory " + q(Core.AppDir),
                "$t = New-ScheduledTaskTrigger -AtLogOn -User " + q(user),
                "$p = New-ScheduledTaskPrincipal -UserId " + q(user) + " -LogonType Interactive -RunLevel Highest",
                "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew",
                "Register-ScheduledTask -TaskName " + q(TaskName) + " -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null",
                "Start-ScheduledTask -TaskName " + q(TaskName)
            });
        }

        /// <summary>Starts the already-registered task without a UAC prompt. False if it isn't registered.</summary>
        public static bool TryStart()
        {
            try
            {
                using (var p = Process.Start(new ProcessStartInfo("schtasks.exe", "/run /tn \"" + TaskName + "\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }))
                {
                    p.WaitForExit(10000);
                    return p.ExitCode == 0;
                }
            }
            catch { return false; }
        }
    }

    class DbListView : ListView
    {
        public DbListView()
        {
            DoubleBuffered = true;
            View = View.Details;
            FullRowSelect = true;
            HideSelection = false;
            MultiSelect = false;
            GridLines = false;
        }
    }

    // ===================================================================== rule editor

    class RuleForm : Form
    {
        public Rule Result;
        readonly List<NetInfo> nets;
        readonly TextBox txtName = new TextBox(), txtExe = new TextBox(), txtArgs = new TextBox();
        readonly ComboBox cboNet = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly CheckBox chkDelay = new CheckBox { Text = "Delayed injection (try this if the app crashes or misbehaves when launched pinned)", AutoSize = true };
        readonly CheckBox chkStartup = new CheckBox { Text = "Launch it pinned when NetSplit starts with Windows", AutoSize = true };

        public RuleForm(Rule r, List<NetInfo> nets)
        {
            this.nets = nets;
            Text = r == null ? "Pin an app to a connection" : "Edit " + r.Name;
            Font = new Font("Segoe UI", 9.5f);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            var t = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Padding = new Padding(14), Dock = DockStyle.Fill };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 420));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Func<string, Label> lbl = s => new Label { Text = s, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 8, 10, 4) };
            foreach (var tb in new[] { txtName, txtExe, txtArgs }) tb.Dock = DockStyle.Fill;
            cboNet.Dock = DockStyle.Fill;

            var browse = new Button { Text = "Browse…", AutoSize = true };
            browse.Click += delegate
            {
                using (var d = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe", Title = "Choose the app's .exe" })
                {
                    if (File.Exists(txtExe.Text)) d.InitialDirectory = Path.GetDirectoryName(txtExe.Text);
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    txtExe.Text = d.FileName;
                    if (txtName.Text.Trim() == "")
                    {
                        string n = null;
                        try { n = FileVersionInfo.GetVersionInfo(d.FileName).ProductName; } catch { }
                        txtName.Text = string.IsNullOrWhiteSpace(n) ? Path.GetFileNameWithoutExtension(d.FileName) : n.Trim();
                    }
                }
            };

            t.Controls.Add(lbl("Program"), 0, 0); t.Controls.Add(txtExe, 1, 0); t.Controls.Add(browse, 2, 0);
            t.Controls.Add(lbl("Name"), 0, 1); t.Controls.Add(txtName, 1, 1);
            t.Controls.Add(lbl("Arguments"), 0, 2); t.Controls.Add(txtArgs, 1, 2);
            t.Controls.Add(lbl("Use connection"), 0, 3); t.Controls.Add(cboNet, 1, 3);
            t.Controls.Add(chkDelay, 1, 4); t.SetColumnSpan(chkDelay, 2);
            t.Controls.Add(chkStartup, 1, 5); t.SetColumnSpan(chkStartup, 2);

            var ok = new Button { Text = "Save", AutoSize = true, DialogResult = DialogResult.None };
            var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
            var btns = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
            btns.Controls.Add(cancel); btns.Controls.Add(ok);
            t.Controls.Add(btns, 0, 6); t.SetColumnSpan(btns, 3);
            Controls.Add(t);
            AcceptButton = ok; CancelButton = cancel;

            foreach (var n in nets) cboNet.Items.Add(n.Label + "  ·  " + n.Ip);
            if (r != null)
            {
                txtName.Text = r.Name; txtExe.Text = r.ExePath; txtArgs.Text = r.Args;
                chkDelay.Checked = r.DelayInject; chkStartup.Checked = r.LaunchAtStartup;
                var cur = Core.Resolve(r, nets);
                if (cur != null) cboNet.SelectedIndex = nets.IndexOf(cur);
                else { cboNet.Items.Add(r.NetworkLabel + " (not connected)"); cboNet.SelectedIndex = cboNet.Items.Count - 1; }
            }
            else
            {
                var tether = nets.FirstOrDefault(n => n.Kind == "Phone USB tether");
                if (cboNet.Items.Count > 0) cboNet.SelectedIndex = tether != null ? nets.IndexOf(tether) : 0;
            }

            ok.Click += delegate
            {
                if (!File.Exists(txtExe.Text.Trim())) { MessageBox.Show(this, "Choose the app's .exe file.", "NetSplit"); return; }
                if (txtName.Text.Trim() == "") { MessageBox.Show(this, "Give the app a name.", "NetSplit"); return; }
                if (cboNet.SelectedIndex < 0) { MessageBox.Show(this, "Choose a connection.", "NetSplit"); return; }
                Result = r ?? new Rule();
                Result.Name = txtName.Text.Trim();
                Result.ExePath = txtExe.Text.Trim();
                Result.Args = txtArgs.Text.Trim();
                Result.DelayInject = chkDelay.Checked;
                Result.LaunchAtStartup = chkStartup.Checked;
                if (cboNet.SelectedIndex < nets.Count)
                {
                    var n = nets[cboNet.SelectedIndex];
                    Result.NetworkGuid = n.Guid; Result.NetworkDesc = n.Desc; Result.NetworkLabel = n.Label;
                }
                DialogResult = DialogResult.OK;
            };
        }
    }

    // ===================================================================== main window

    class MainForm : Form
    {
        readonly Config cfg;
        readonly bool startHidden;
        readonly Icon appIcon;
        Font boldFont;
        readonly Label summary = new Label { AutoSize = true, Font = new Font("Segoe UI Semibold", 11f), Margin = new Padding(0, 0, 0, 4) };
        readonly Label hint = new Label { AutoSize = true, ForeColor = Color.FromArgb(180, 83, 9), Margin = new Padding(0, 0, 0, 8) };
        readonly DbListView netList = new DbListView { Dock = DockStyle.Fill };
        readonly DbListView ruleList = new DbListView { Dock = DockStyle.Fill };
        readonly Label status = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(0, 8, 0, 0) };
        readonly CheckBox chkStartup = new CheckBox { Text = "Start NetSplit with Windows (it waits in the tray)", AutoSize = true };
        readonly NotifyIcon tray = new NotifyIcon();
        readonly List<Button> busyButtons = new List<Button>();
        readonly Dictionary<string, long[]> lastBytes = new Dictionary<string, long[]>();
        readonly Dictionary<string, int> ping = new Dictionary<string, int>();
        readonly Dictionary<string, int> lastLevel = new Dictionary<string, int>();
        System.Threading.Timer poll;
        int polling;
        volatile bool rescan = true, reprobe = true;
        DateTime lastProbe = DateTime.MinValue, lastScan = DateTime.MinValue;
        List<NetInfo> bgNets = new List<NetInfo>();
        List<NetInfo> uiNets = new List<NetInfo>();
        Dictionary<string, int> uiPings = new Dictionary<string, int>();
        bool reallyExit;
        volatile bool agentUp = true;
        Button btnService;
        DateTime startupUntil = DateTime.MinValue;
        readonly HashSet<string> startupDone = new HashSet<string>();

        public MainForm(Config cfg, bool startHidden)
        {
            this.cfg = cfg;
            this.startHidden = startHidden;
            using (var b = Core.DrawIcon(32)) appIcon = Icon.FromHandle(b.GetHicon());

            Text = "NetSplit";
            Icon = appIcon;
            Font = new Font("Segoe UI", 9.5f);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(1000, 640);
            MinimumSize = new Size(780, 520);
            StartPosition = FormStartPosition.CenterScreen;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(14, 12, 14, 10) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Func<string, Label> header = s => new Label { Text = s, AutoSize = true, Font = new Font("Segoe UI Semibold", 9.5f), ForeColor = Color.FromArgb(55, 65, 81), Margin = new Padding(0, 10, 0, 4) };

            netList.Columns.Add("Connection", 265);
            netList.Columns.Add("IP address", 125);
            netList.Columns.Add("Internet", 95);
            netList.Columns.Add("Download", 110, HorizontalAlignment.Right);
            netList.Columns.Add("Upload", 105, HorizontalAlignment.Right);
            netList.Columns.Add("Role", 240);

            ruleList.Columns.Add("App", 170);
            ruleList.Columns.Add("Pinned to", 230);
            ruleList.Columns.Add("Status", 540);

            var netBtns = Flow();
            var bDefault = Btn(netBtns, "★ Make selected the default for everything", OnMakeDefault, true);
            Btn(netBtns, "Let Windows decide (undo)", OnReset, true);
            Btn(netBtns, "Re-check internet", delegate { rescan = reprobe = true; lock (ping) ping.Clear(); }, false);

            var ruleBtns = Flow();
            Btn(ruleBtns, "▶ Launch pinned", OnLaunch, true);
            Btn(ruleBtns, "Add app…", OnAdd, false);
            Btn(ruleBtns, "Edit…", OnEdit, false);
            Btn(ruleBtns, "Remove", OnRemove, false);
            Btn(ruleBtns, "Desktop shortcut", OnShortcut, false);
            btnService = Btn(ruleBtns, "⚙ Turn on pinning service", OnService, true);

            var footer = Flow();
            footer.Controls.Add(chkStartup);
            chkStartup.Checked = Core.StartsWithWindows;
            chkStartup.CheckedChanged += delegate
            {
                try { Core.StartsWithWindows = chkStartup.Checked; }
                catch (Exception ex) { SetStatus("Couldn't change startup setting: " + ex.Message); }
            };

            root.Controls.Add(summary, 0, 0);
            root.Controls.Add(hint, 0, 1);
            root.Controls.Add(header("Internet connections on this PC"), 0, 2);
            root.Controls.Add(netList, 0, 3);
            root.Controls.Add(netBtns, 0, 4);
            root.Controls.Add(header("Apps pinned to a connection (everything else uses the default)"), 0, 5);
            root.Controls.Add(ruleList, 0, 6);
            root.Controls.Add(ruleBtns, 0, 7);
            var bottom = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
            bottom.Controls.Add(footer);
            bottom.Controls.Add(status);
            root.Controls.Add(bottom, 0, 8);
            Controls.Add(root);
            Resize += delegate
            {
                int w = Math.Max(200, root.ClientSize.Width - 40);
                summary.MaximumSize = hint.MaximumSize = status.MaximumSize = new Size(w, 0);
            };

            ruleList.DoubleClick += delegate { OnEdit(null, null); };
            netList.DoubleClick += delegate { bDefault.PerformClick(); };

            // tray
            tray.Icon = appIcon;
            tray.Text = "NetSplit";
            tray.Visible = true;
            tray.DoubleClick += delegate { ShowWindow(); };
            tray.BalloonTipClicked += delegate { ShowWindow(); };
            var menu = new ContextMenuStrip();
            menu.Opening += delegate { BuildTrayMenu(menu); };
            tray.ContextMenuStrip = menu;

            NetworkChange.NetworkAddressChanged += delegate { rescan = reprobe = true; };
            SystemEvents_Resumed();

            if (startHidden)
            {
                startupUntil = DateTime.UtcNow.AddMinutes(3);
            }
            ThreadPool.QueueUserWorkItem(delegate { if (!Agent.IsRunning()) Agent.TryStart(); });
            poll = new System.Threading.Timer(Poll, null, 0, 1000);
        }

        void SystemEvents_Resumed()
        {
            SystemEvents.PowerModeChanged += (s, e) => { if (e.Mode == PowerModes.Resume) rescan = reprobe = true; };
        }

        static FlowLayoutPanel Flow()
        {
            return new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0, 6, 0, 0) };
        }

        Button Btn(FlowLayoutPanel panel, string text, EventHandler click, bool busy)
        {
            var b = new Button { Text = text, AutoSize = true, Padding = new Padding(6, 2, 6, 2), Margin = new Padding(0, 0, 8, 0) };
            b.Click += click;
            panel.Controls.Add(b);
            if (busy) busyButtons.Add(b);
            return b;
        }

        protected override void SetVisibleCore(bool value)
        {
            if (startHidden && !IsHandleCreated) { CreateHandle(); value = false; }
            base.SetVisibleCore(value);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!reallyExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                if (!cfg.TrayHintShown)
                {
                    cfg.TrayHintShown = true;
                    try { Core.SaveConfig(cfg); } catch { }
                    tray.ShowBalloonTip(5000, "NetSplit is still running", "It keeps watching your pinned apps from the tray. Right-click the icon to exit.", ToolTipIcon.Info);
                }
                return;
            }
            poll.Dispose();
            tray.Visible = false;
            tray.Dispose();
            base.OnFormClosing(e);
        }

        public void ShowWindow()
        {
            if (InvokeRequired) { BeginInvoke(new Action(ShowWindow)); return; }
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
        }

        void BuildTrayMenu(ContextMenuStrip menu)
        {
            menu.Items.Clear();
            menu.Items.Add("Open NetSplit", null, delegate { ShowWindow(); });
            menu.Items.Add(new ToolStripSeparator());
            List<Rule> rules;
            lock (cfg) rules = cfg.Rules.ToList();
            foreach (var r in rules)
            {
                var rr = r;
                var net = Core.Resolve(r, uiNets);
                menu.Items.Add(string.Format("Launch {0} on {1}", r.Name, net != null ? net.Label : r.NetworkLabel), null, delegate { LaunchRule(rr); });
            }
            if (rules.Count > 0) menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, delegate { reallyExit = true; Close(); });
        }

        void SetStatus(string s) { status.Text = DateTime.Now.ToString("HH:mm") + "  " + s; }

        // ------------------------------------------------------------ polling (background)

        void Poll(object _)
        {
            if (Interlocked.Exchange(ref polling, 1) == 1) return;
            try
            {
                var now = DateTime.UtcNow;
                if (rescan || (now - lastScan).TotalSeconds >= 5)
                {
                    rescan = false;
                    bgNets = Core.Scan();
                    lastScan = now;
                }
                var nets = bgNets;

                var rates = new Dictionary<string, double[]>();
                foreach (var n in nets)
                {
                    try
                    {
                        var st = n.Nic.GetIPStatistics();
                        long rx = st.BytesReceived, tx = st.BytesSent;
                        long[] prev;
                        if (lastBytes.TryGetValue(n.Guid, out prev))
                        {
                            double dt = (now.Ticks - prev[2]) / (double)TimeSpan.TicksPerSecond;
                            if (dt > 0.2) rates[n.Guid] = new[] { Math.Max(0, (rx - prev[0]) / dt), Math.Max(0, (tx - prev[1]) / dt) };
                        }
                        lastBytes[n.Guid] = new[] { rx, tx, now.Ticks };
                    }
                    catch { }
                }

                if (reprobe || (now - lastProbe).TotalSeconds >= 20)
                {
                    reprobe = false;
                    lastProbe = now;
                    foreach (var n in nets)
                    {
                        var nn = n;
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            int ms = Core.Probe(nn.Ip);
                            lock (ping) ping[nn.Guid] = ms;
                        });
                    }
                }

                var repinned = Core.RepinChildren(cfg);
                var conns = Core.TcpConnections();
                List<Rule> rules;
                lock (cfg) rules = cfg.Rules.ToList();
                bool agent = Agent.IsRunning();
                agentUp = agent;
                var views = rules.Select(r => Core.Status(r, nets, conns, agent)).ToList();
                Dictionary<string, int> pings;
                lock (ping) pings = new Dictionary<string, int>(ping);

                if (IsHandleCreated && !IsDisposed)
                    BeginInvoke(new Action(() =>
                    {
                        foreach (var name in repinned)
                        {
                            SetStatus(name + " restarted itself; NetSplit pinned the new copy too.");
                            if (!Visible) tray.ShowBalloonTip(5000, "NetSplit", name + " restarted itself and has been pinned again.", ToolTipIcon.Info);
                        }
                        Apply(nets, rates, pings, views);
                    }));
            }
            catch { }
            finally { polling = 0; }
        }

        // ------------------------------------------------------------ UI refresh

        void Apply(List<NetInfo> nets, Dictionary<string, double[]> rates, Dictionary<string, int> pings, List<RuleView> views)
        {
            uiNets = nets;
            uiPings = pings;
            var def = Core.DefaultOf(nets);

            // summary + hints
            if (nets.Count == 0) summary.Text = "No internet connection found.";
            else
            {
                var pinned = views.Where(v => Core.Resolve(v.Rule, nets) != null && Core.Resolve(v.Rule, nets) != def)
                                  .Select(v => v.Rule.Name + " → " + Core.Resolve(v.Rule, nets).Kind).ToList();
                summary.Text = "Everything uses " + def.Kind + " by default" +
                               (pinned.Count > 0 ? ".   Pinned: " + string.Join(",  ", pinned) : ".");
            }
            var hints = new List<string>();
            if (def != null && !def.HasV6Default)
            {
                var leak = nets.Where(n => n != def && n.HasV6Default && !n.V6Off).ToList();
                if (leak.Count > 0)
                    hints.Add(string.Format("⚠ {0} has IPv6 and {1} doesn't, so YouTube/Google can still go over {0}. Click “Make selected the default” on {1} to fix it.", leak[0].Kind, def.Kind));
            }
            foreach (var n in nets)
            {
                int ms;
                if (pings.TryGetValue(n.Guid, out ms) && ms < 0)
                    hints.Add(string.Format("⚠ {0} is connected but can't reach the internet{1}.", n.Label,
                        n.Kind == "Wi-Fi" ? " (the router has no internet: check the router or your ISP)" : ""));
            }
            if (def != null && def.Kind == "Phone USB tether" && nets.Any(n => n.Kind == "Wi-Fi"))
                hints.Add("Tip: make Wi-Fi the default and pin your big downloads to the phone, so browsing doesn't compete with them.");
            if (views.Any(v => v.Rule.NetworkGuid == (def != null ? def.Guid : null)))
                hints.Add("Note: an app is pinned to the default connection, so pinning it changes nothing.");
            if (!agentUp && views.Count > 0)
                hints.Insert(0, "⚠ The pinning service is off, so pinned apps can leak onto the default connection. Click “⚙ Turn on pinning service”.");
            btnService.Visible = !agentUp;
            hint.Text = string.Join("\n", hints);
            hint.Visible = hints.Count > 0;

            // networks list
            netList.BeginUpdate();
            var keys = new HashSet<string>(nets.Select(n => n.Guid));
            for (int i = netList.Items.Count - 1; i >= 0; i--)
                if (!keys.Contains(netList.Items[i].Name)) netList.Items.RemoveAt(i);
            foreach (var n in nets)
            {
                var item = netList.Items[n.Guid] ?? netList.Items.Add(new ListViewItem(new string[6]) { Name = n.Guid });
                int ms;
                string inet = !pings.TryGetValue(n.Guid, out ms) ? "checking…" : ms < 0 ? "✖ none" : "✔ " + ms + " ms";
                double[] rt;
                rates.TryGetValue(n.Guid, out rt);
                var users = views.Where(v => Core.Resolve(v.Rule, nets) == n).Select(v => v.Rule.Name).ToList();
                string role = n == def ? "★ Default: everything uses this" : "Standby";
                if (users.Count > 0 && n != def) role = "Pinned apps only: " + string.Join(", ", users);
                if (n.V6Off) role += "  ·  IPv6 off";
                if (!n.AutoMetric) role += "  ·  priority " + n.IfMetric;
                Set(item, 0, n.Label);
                Set(item, 1, n.Ip.ToString());
                Set(item, 2, inet);
                Set(item, 3, rt != null ? "↓ " + Core.FormatRate(rt[0]) : "");
                Set(item, 4, rt != null ? "↑ " + Core.FormatRate(rt[1]) : "");
                Set(item, 5, role);
                item.ToolTipText = n.Desc;
                if (boldFont == null) boldFont = new Font(netList.Font, FontStyle.Bold);
                var font = n == def ? boldFont : netList.Font;
                if (item.Font != font) item.Font = font;
                var color = ms < 0 && pings.ContainsKey(n.Guid) ? Color.Firebrick : SystemColors.WindowText;
                if (item.ForeColor != color) item.ForeColor = color;
            }
            if (netList.SelectedItems.Count == 0 && netList.Items.Count > 0)
            {
                var pick = nets.FirstOrDefault(n => n.Kind == "Wi-Fi") ?? nets[0];
                var it = netList.Items[pick.Guid];
                if (it != null) it.Selected = true;
            }
            netList.EndUpdate();

            // rules list
            ruleList.BeginUpdate();
            while (ruleList.Items.Count > views.Count) ruleList.Items.RemoveAt(ruleList.Items.Count - 1);
            for (int i = 0; i < views.Count; i++)
            {
                var v = views[i];
                var item = i < ruleList.Items.Count ? ruleList.Items[i] : ruleList.Items.Add(new ListViewItem(new string[3]));
                item.Tag = v.Rule;
                Set(item, 0, v.Rule.Name);
                Set(item, 1, v.NetText);
                Set(item, 2, v.Text);
                var c = v.Level == 1 ? Color.FromArgb(21, 128, 61) : v.Level == 2 ? Color.FromArgb(194, 65, 12) : SystemColors.WindowText;
                if (item.ForeColor != c) item.ForeColor = c;

                // tray warning when a running app stops being pinned (e.g. Steam restarted itself)
                int prev;
                lastLevel.TryGetValue(v.Rule.Name, out prev);
                if (v.Level == 2 && prev != 2 && !Visible)
                    tray.ShowBalloonTip(8000, v.Rule.Name + " isn't on " + v.Rule.NetworkLabel, v.Text + "\nOpen NetSplit and click Launch pinned.", ToolTipIcon.Warning);
                lastLevel[v.Rule.Name] = v.Level;
            }
            if (ruleList.SelectedItems.Count == 0 && ruleList.Items.Count > 0) ruleList.Items[0].Selected = true;
            ruleList.EndUpdate();

            tray.Text = Truncate("NetSplit: default " + (def != null ? def.Kind : "none"), 63);

            // apps marked "launch when NetSplit starts"
            if (DateTime.UtcNow < startupUntil)
            {
                foreach (var v in views)
                {
                    var r = v.Rule;
                    if (!r.LaunchAtStartup || startupDone.Contains(r.Name)) continue;
                    if (Core.Resolve(r, nets) == null) continue; // wait for the network to come up
                    startupDone.Add(r.Name);
                    if (v.Text == "Not running") LaunchRule(r, true);
                }
            }
        }

        static string Truncate(string s, int n) { return s.Length <= n ? s : s.Substring(0, n); }

        static void Set(ListViewItem item, int col, string text)
        {
            while (item.SubItems.Count <= col) item.SubItems.Add("");
            if (item.SubItems[col].Text != text) item.SubItems[col].Text = text;
        }

        NetInfo SelectedNet()
        {
            if (netList.SelectedItems.Count == 0) return null;
            string g = netList.SelectedItems[0].Name;
            return uiNets.FirstOrDefault(n => n.Guid == g);
        }

        Rule SelectedRule()
        {
            return ruleList.SelectedItems.Count == 0 ? null : ruleList.SelectedItems[0].Tag as Rule;
        }

        // ------------------------------------------------------------ actions

        void RunBusy(string what, Func<string> work, string done)
        {
            foreach (var b in busyButtons) b.Enabled = false;
            SetStatus(what);
            ThreadPool.QueueUserWorkItem(delegate
            {
                string err;
                try { err = work(); }
                catch (Exception ex) { err = ex.Message; }
                BeginInvoke(new Action(() =>
                {
                    foreach (var b in busyButtons) b.Enabled = true;
                    rescan = reprobe = true;
                    if (err == null) SetStatus(done);
                    else if (err == "") SetStatus("Cancelled.");
                    else { SetStatus("Problem: " + err); if (Visible) MessageBox.Show(this, err, "NetSplit", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                }));
            });
        }

        void OnMakeDefault(object s, EventArgs e)
        {
            var n = SelectedNet();
            if (n == null) { SetStatus("Select a connection first."); return; }
            int ms;
            if (uiPings.TryGetValue(n.Guid, out ms) && ms < 0 &&
                MessageBox.Show(this, n.Label + " can't reach the internet right now.\n\nIf you make it the default, browsing and every unpinned app will stop working until it comes back.\n\nMake it the default anyway?",
                    "NetSplit", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var nets = uiNets;
            RunBusy("Making " + n.Label + " the default (Windows may ask for permission)…",
                () => Core.MakeDefault(n, nets, cfg),
                n.Label + " is now the default for everything. Pinned apps keep their own connection.");
        }

        void OnReset(object s, EventArgs e)
        {
            var nets = uiNets;
            RunBusy("Handing priority back to Windows…", () => Core.ResetToAutomatic(nets, cfg),
                "Windows decides the default again, and IPv6 is back on where NetSplit had turned it off.");
        }

        bool AskOnUi(string q)
        {
            bool answer = false;
            Invoke(new Action(() =>
            {
                if (!Visible) ShowWindow();
                answer = MessageBox.Show(this, q, "NetSplit", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;
            }));
            return answer;
        }

        void LaunchRule(Rule r, bool silent = false)
        {
            RunBusy("Starting " + r.Name + " pinned to " + r.NetworkLabel + "…",
                () => Core.Launch(r, cfg, silent ? (Func<string, bool>)(q => false) : AskOnUi),
                r.Name + " started, pinned to " + r.NetworkLabel + ".");
        }

        void OnLaunch(object s, EventArgs e)
        {
            var r = SelectedRule();
            if (r == null) { SetStatus("Add an app first."); return; }
            LaunchRule(r);
        }

        void OnAdd(object s, EventArgs e)
        {
            using (var f = new RuleForm(null, uiNets))
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                lock (cfg) cfg.Rules.Add(f.Result);
                Core.SaveConfig(cfg);
                SetStatus(f.Result.Name + " added. Click “Launch pinned” to start it on " + f.Result.NetworkLabel + ".");
            }
        }

        void OnEdit(object s, EventArgs e)
        {
            var r = SelectedRule();
            if (r == null) return;
            using (var f = new RuleForm(r, uiNets))
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                Core.SaveConfig(cfg);
                SetStatus("Saved. If " + r.Name + " is running, launch it again for the change to apply.");
            }
        }

        void OnRemove(object s, EventArgs e)
        {
            var r = SelectedRule();
            if (r == null) return;
            if (MessageBox.Show(this, "Stop pinning " + r.Name + "? (This doesn't close or uninstall it.)", "NetSplit", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            lock (cfg) cfg.Rules.Remove(r);
            Core.SaveConfig(cfg);
            SetStatus(r.Name + " removed.");
        }

        void OnService(object s, EventArgs e)
        {
            RunBusy("Installing the pinning service (Windows will ask for permission once)…", Agent.Install,
                "Pinning service is on. It starts by itself every time you log in.");
        }

        void OnShortcut(object s, EventArgs e)
        {
            var r = SelectedRule();
            if (r == null) return;
            try
            {
                var net = Core.Resolve(r, uiNets);
                string path = Core.CreateShortcut(r, net != null ? net.Kind : r.NetworkLabel);
                SetStatus("Desktop shortcut created: " + Path.GetFileNameWithoutExtension(path) + ". Use it instead of the normal " + r.Name + " icon.");
            }
            catch (Exception ex) { SetStatus("Couldn't create the shortcut: " + ex.Message); }
        }
    }

    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "--write-icon") { Core.WriteIco(args[1]); return 0; }
            if (args.Length == 1 && args[0] == "--agent") return Agent.Run();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var cfg = Core.LoadConfig();
            bool firstRun = cfg == null;
            if (firstRun) cfg = new Config();

            // Desktop shortcut mode: NetSplit.exe --launch "Steam"
            if (args.Length == 2 && args[0] == "--launch")
            {
                var r = cfg.Rules.FirstOrDefault(x => string.Equals(x.Name, args[1], StringComparison.OrdinalIgnoreCase));
                if (r == null) { MessageBox.Show("NetSplit has no app called \"" + args[1] + "\".", "NetSplit"); return 1; }
                string err = Core.Launch(r, cfg, q => MessageBox.Show(q, "NetSplit", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes);
                if (!string.IsNullOrEmpty(err)) { MessageBox.Show(err, "NetSplit", MessageBoxButtons.OK, MessageBoxIcon.Warning); return 1; }
                if (err == null)
                {
                    // Keep NetSplit running in the tray so it can re-pin the app if it restarts itself.
                    bool running;
                    try { Mutex.OpenExisting("NetSplit.SingleInstance").Dispose(); running = true; }
                    catch { running = false; }
                    if (!running) Process.Start(Application.ExecutablePath, "--tray");
                }
                return 0;
            }

            bool created;
            using (var mutex = new Mutex(true, "NetSplit.SingleInstance", out created))
            {
                if (!created)
                {
                    try { EventWaitHandle.OpenExisting("NetSplit.Show").Set(); } catch { }
                    return 0;
                }

                if (firstRun)
                {
                    // Smart default: pin Steam to the phone tether if both exist.
                    string steam = null;
                    try
                    {
                        using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                            if (k != null) steam = k.GetValue("SteamExe") as string;
                    }
                    catch { }
                    var tether = Core.Scan().FirstOrDefault(n => n.Kind == "Phone USB tether");
                    if (steam != null && File.Exists(steam) && tether != null)
                        cfg.Rules.Add(new Rule
                        {
                            Name = "Steam",
                            ExePath = Path.GetFullPath(steam),
                            NetworkGuid = tether.Guid,
                            NetworkDesc = tether.Desc,
                            NetworkLabel = tether.Label
                        });
                    try { Core.SaveConfig(cfg); } catch { }
                }

                bool tray = args.Contains("--tray");
                var form = new MainForm(cfg, tray);
                var showEvt = new EventWaitHandle(false, EventResetMode.AutoReset, "NetSplit.Show");
                var t = new Thread(() => { while (showEvt.WaitOne()) form.ShowWindow(); }) { IsBackground = true };
                t.Start();
                Application.Run(form);
            }
            return 0;
        }
    }
}
