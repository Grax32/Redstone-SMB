using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using NLog.Extensions.Logging;

namespace RedstoneSmb.Log
{
    public static class Logger
    {
        public static ILogger LoggerInstance => GetLogger();

        private static ILogger GetLogger()
        {
            using (var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("LoggingConsoleApp.Program", LogLevel.Debug);

                builder.AddNLog();
            }))
            {
                var nlogConfig = new NLog.Config.LoggingConfiguration();
                var logfile = new NLog.Targets.FileTarget("logfile") { FileName = "logfile.txt" };

                nlogConfig.AddTarget(logfile);
                nlogConfig.AddRuleForAllLevels(logfile);

                return loggerFactory.CreateLogger("Redstone-SMB");
            }
        }

        public static void Log(LogLevel logLevel, string message, params object[] args)
        {
            LoggerInstance.Log(logLevel, message, args);
        }

        public static void Log(LogLevel logLevel, Exception ex, params object[] args)
        {
            LoggerInstance.Log(logLevel, FormatException(ex, args), args);
        }

        private static string FormatException(Exception ex, object[] args)
        {
            var stringArgs = args?.Select(arg => arg?.ToString())?.ToArray();

            return JsonConvert.SerializeObject(new
            {
                ex.Message,
                ex.StackTrace,
                InnerMessage = ex.InnerException?.Message,
                ex.Source,
                Arguments = stringArgs
            }, Formatting.Indented);
        }
    }
}
