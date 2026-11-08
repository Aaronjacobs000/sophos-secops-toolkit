// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/fusion/queries/search.ts at release 0.9.2. MIT License, Copyright (c) 2026; the full notice
// is in LICENSE-MIT at the root of this package. (SecOps Toolkit local modification, 29/10/2026.)

/**
 * Search GraphQL API v1 documents (released 12/10/2026): createSearch,
 * getOrCreateSearch, search and searchResults. A search is asynchronous:
 * start it, poll search(urn) until status is COMPLETE, check
 * outcome.success, then page searchResults by cursor.
 *
 * The two start operations are mutations. They start a search job and change
 * no tenant setting. SecOps Toolkit's read-only guard allows exactly these two
 * documents, compared character for character, so an edit here has to be
 * made in backend/src/sophos/guard.ts as well (a test checks they match).
 */

export const CREATE_SEARCH = `mutation CreateSearch($input: CreateSearchInput) {
  createSearch(input: $input) {
    urn
    status
    errors
    outcome { success errors { urn errors } }
    searchPartitions { urn schemaType status errors }
    createTime
    expireTime
  }
}`;

export const GET_OR_CREATE_SEARCH = `mutation GetOrCreateSearch($input: CreateSearchInput) {
  getOrCreateSearch(input: $input) {
    urn
    status
    errors
    outcome { success errors { urn errors } }
    searchPartitions { urn schemaType status errors }
    createTime
    expireTime
  }
}`;

export const SEARCH_STATUS = `query SearchStatus($urn: URN!) {
  search(urn: $urn) {
    urn
    status
    errors
    outcome { success errors { urn errors } }
    searchPartitions { urn schemaType status errors }
    createTime
    expireTime
  }
}`;

export const SEARCH_RESULTS = `query SearchResults($urn: URN!, $cursor: String, $limit: Int) {
  searchResults(urn: $urn, cursor: $cursor, limit: $limit) {
    values
    totals { total { value } subtotals { schemaType value } }
    nextCursor
  }
}`;
