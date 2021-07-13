/* Copyright (C) 2016-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Threading;

namespace RedstoneSmb.Utilities.Generics
{
    public class BlockingQueue<T>
    {
        private readonly Queue<T> _mQueue = new Queue<T>();
        private bool _mStopping;

        public int Count { get; private set; }

        public void Enqueue(T item)
        {
            lock (_mQueue)
            {
                _mQueue.Enqueue(item);
                Count++;
                if (_mQueue.Count == 1) Monitor.Pulse(_mQueue);
            }
        }

        public void Enqueue(List<T> items)
        {
            if (items.Count == 0) return;
            lock (_mQueue)
            {
                foreach (var item in items)
                {
                    _mQueue.Enqueue(item);
                    Count++;
                }

                if (_mQueue.Count == items.Count) Monitor.Pulse(_mQueue);
            }
        }

        /// <returns>Will return false if the BlockingQueue is stopped</returns>
        public bool TryDequeue(out T item)
        {
            lock (_mQueue)
            {
                while (_mQueue.Count == 0)
                {
                    Monitor.Wait(_mQueue);
                    if (_mStopping)
                    {
                        item = default;
                        return false;
                    }
                }

                item = _mQueue.Dequeue();
                Count--;
                return true;
            }
        }

        public void Stop()
        {
            lock (_mQueue)
            {
                _mStopping = true;
                Monitor.PulseAll(_mQueue);
            }
        }
    }
}