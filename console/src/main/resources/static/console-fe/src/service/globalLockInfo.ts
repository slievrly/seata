/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import request from '@/utils/request';

export type GlobalLockParam = {
  xid?: string,
  tableName?: string,
  transactionId?: string,
  branchId?: string,
  pk?: string,
  resourceId?: string,
  pageSize: number,
  pageNum: number,
  timeStart?: number,
  timeEnd?: number
};

export default async function fetchData(params:GlobalLockParam):Promise<any> {
  let result = await request('/console/globalLock/query', {
    method: 'get',
    params,
  });

  return result;
}

export async function deleteData(params: GlobalLockParam): Promise<any> {
  let result = await request('/console/globalLock/delete', {
    method: 'delete',
    params,
  });
  return result;
}

export async function checkData(params: GlobalLockParam): Promise<any> {
  const xid = params.xid
  const branchId = params.branchId

  let result = await request('/console/globalLock/check', {
    method: 'get',
    params: {
      xid,
      branchId
    },
  });
  return result;
}
