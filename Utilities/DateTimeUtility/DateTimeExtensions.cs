using System;
using System.Collections.Generic;
using System.Text;

namespace Utilities.DateTimeUtility
{
    public static class DateTimeExtensions
    {
        public static short GetUtcOffset(this System.DateTime dateTime)
        {
            return (short)-TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow).TotalMinutes;
        }
    }
}
