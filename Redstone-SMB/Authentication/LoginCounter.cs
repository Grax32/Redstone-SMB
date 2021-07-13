/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace RedstoneSmb.Authentication
{
    public class LoginCounter
    {
        private readonly Dictionary<string, LoginEntry> _mLoginEntries = new Dictionary<string, LoginEntry>();
        private readonly TimeSpan _mLoginWindowDuration;

        private readonly int _mMaxLoginAttemptsInWindow;

        public LoginCounter(int maxLoginAttemptsInWindow, TimeSpan loginWindowDuration)
        {
            _mMaxLoginAttemptsInWindow = maxLoginAttemptsInWindow;
            _mLoginWindowDuration = loginWindowDuration;
        }

        public bool HasRemainingLoginAttempts(string userId)
        {
            return HasRemainingLoginAttempts(userId, false);
        }

        public bool HasRemainingLoginAttempts(string userId, bool incrementCount)
        {
            lock (_mLoginEntries)
            {
                LoginEntry entry;
                if (_mLoginEntries.TryGetValue(userId, out entry))
                {
                    if (entry.LoginWindowStartDt.Add(_mLoginWindowDuration) >= DateTime.UtcNow)
                    {
                        // Existing login Window
                        if (incrementCount) entry.NumberOfAttempts++;
                    }
                    else
                    {
                        // New login Window
                        if (!incrementCount) return true;
                        entry.LoginWindowStartDt = DateTime.UtcNow;
                        entry.NumberOfAttempts = 1;
                    }
                }
                else
                {
                    if (!incrementCount) return true;
                    entry = new LoginEntry();
                    entry.LoginWindowStartDt = DateTime.UtcNow;
                    entry.NumberOfAttempts = 1;
                    _mLoginEntries.Add(userId, entry);
                }

                return entry.NumberOfAttempts < _mMaxLoginAttemptsInWindow;
            }
        }

        public class LoginEntry
        {
            public DateTime LoginWindowStartDt;
            public int NumberOfAttempts;
        }
    }
}