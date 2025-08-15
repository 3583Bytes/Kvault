using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KVault
{
    public sealed class CrossPlatformClipboardService : IClipboardService
    {
        public void SetText(string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                RunPipe("cmd.exe", "/c clip", text);
                return;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                RunPipe("pbcopy", null, text);
                return;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // Try xclip, then xsel
                try { RunPipe("xclip", "-selection clipboard", text); }
                catch { RunPipe("xsel", "-b", text); }
                return;
            }

            throw new PlatformNotSupportedException("Clipboard unsupported on this platform.");
        }

        private static void RunPipe(string fileName, string? arguments, string input)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments ?? string.Empty,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {fileName}");
            using var sw = p.StandardInput;
            sw.Write(input);
            sw.Flush();
            sw.Close();
            p.WaitForExit();
            if (p.ExitCode != 0)
                throw new InvalidOperationException($"Clipboard command '{fileName} {arguments}' exited with {p.ExitCode}.");
        }
    }
}