/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace RedstoneSmb.Utilities.Generics
{
    public class KeyValuePairList<TKey, TValue> : List<KeyValuePair<TKey, TValue>>
    {
        public KeyValuePairList()
        {
        }

        private KeyValuePairList(List<KeyValuePair<TKey, TValue>> collection) : base(collection)
        {
        }

        public List<TKey> Keys
        {
            get
            {
                var result = new List<TKey>();
                foreach (var entity in this) result.Add(entity.Key);
                return result;
            }
        }

        public List<TValue> Values
        {
            get
            {
                var result = new List<TValue>();
                foreach (var entity in this) result.Add(entity.Value);
                return result;
            }
        }

        public bool ContainsKey(TKey key)
        {
            return IndexOfKey(key) != -1;
        }

        public int IndexOfKey(TKey key)
        {
            for (var index = 0; index < Count; index++)
                if (this[index].Key.Equals(key))
                    return index;

            return -1;
        }

        public TValue ValueOf(TKey key)
        {
            for (var index = 0; index < Count; index++)
                if (this[index].Key.Equals(key))
                    return this[index].Value;

            return default;
        }

        public void Add(TKey key, TValue value)
        {
            Add(new KeyValuePair<TKey, TValue>(key, value));
        }

        public new KeyValuePairList<TKey, TValue> GetRange(int index, int count)
        {
            return new KeyValuePairList<TKey, TValue>(base.GetRange(index, count));
        }
    }
}