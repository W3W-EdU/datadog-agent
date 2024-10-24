using WixSharp;

namespace WixSetup.Datadog_Agent
{
    public class AgentBinaries
    {
        private readonly string _binSource;
        public string Agent => $@"{_binSource}\agent\agent.exe";
        public string Tray => $@"{_binSource}\agent\ddtray.exe";
        public Id TrayId => new("ddtray");
        public string ProcessAgent => $@"{_binSource}\agent\process-agent.exe";
        public string SystemProbe => $@"{_binSource}\agent\system-probe.exe";
        public string TraceAgent => $@"{_binSource}\agent\trace-agent.exe";
        // this will only be actually used when the procmon driver is present
        // if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WINDOWS_DDPROCMON_DRIVER")))
        public string SecurityAgent => $@"{_binSource}\agent\security-agent.exe";
        public string LibDatadogAgentThree => $@"{_binSource}\agent\libdatadog-agent-three.dll";

        public AgentBinaries(string binSource, string installerSource)
        {
            _binSource = binSource;
        }
    }
}
