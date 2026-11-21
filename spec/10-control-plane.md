# 10 - Control Plane

Status: Draft
Version: 1.0-draft.1

This document specifies the optional, slow-moving information that participants
share: device profiles, trust between federation participants, links between
identities, and coverage statements. It uses AT Protocol records described by the
lexicons in `lexicons/`, plus one Nostr event for identity linking.

Nothing in 00-09 depends on this document. A home with no internet connection,
or one that never enables these features, works fully.

## 1. Goals (informative)

- A new sensor design works in everyone's Home Assistant as soon as its author
  publishes a profile, with no integration release.
- Federation participants can decide whom to trust with their airtime.
- People can see where community coverage exists, without anyone revealing an
  address.

## 2. Principles

- **Data only.** Everything here is declarative data. A server MUST validate it
  against the lexicons and MUST NOT execute anything from it.
- **No sensor data.** Readings, frames, timings and device lists MUST NOT be
  published through the control plane. Live traffic stays in 09.
- **Opt in.** Publishing anything is a user choice. Reading public profiles is
  the only default behavior, and only from sources the user trusts (4.2).
- **Pluggable.** The same documents MAY be carried over ActivityPub or simply
  shared as files. AT Protocol is the specified transport because its records are
  signed by their author's repository and addressable by DID.

## 3. Naming

The lexicons use the NSID authority `org.connectsensors`. AT Protocol resolves an
NSID's authority through DNS, so this requires control of the domain
`connectsensors.org`. **This is provisional:** if the project uses a different
domain, every NSID in this document and in `lexicons/` changes to match before
this document leaves Draft.

| NSID | Record key | Purpose |
|---|---|---|
| `org.connectsensors.deviceProfile` | Profile identifier | Device profiles (section 4) |
| `org.connectsensors.trust` | TID | Trust statements (section 5) |
| `org.connectsensors.coverage` | Publisher Nostr key, hex | Coverage statements (section 6) |

## 4. Device profiles

### 4.1 Publishing

An author publishes each profile as an `org.connectsensors.deviceProfile` record
in their AT Protocol repository, with the profile identifier (03 section 9.1) as
the record key.

- `profileVersion` MUST increase with every change.
- A profile's channels and kinds MUST NOT be changed incompatibly once devices use
  it (for example, changing a channel's kind). Publish a new profile identifier
  instead.
- Profiles with identifiers starting `CS.` are published only by the project's
  own repository.

### 4.2 Resolving

The server keeps an ordered list of *profile sources*: DIDs whose repositories it
reads profiles from.

1. Profiles built into the integration (at least every `CS.` profile) come first.
2. Then profiles the user imported as files.
3. Then each profile source in order, by fetching the record
   `at://<source DID>/org.connectsensors.deviceProfile/<profile id>`.

The first match wins. The default source list contains only the project's DID
(to be decided). Adding a source is a user action, shown with the source's
handle, since a source can describe how devices appear in the user's home.

A server SHOULD check its sources for newer `profileVersion`s of the profiles it
uses once a day, and MUST show the user what changed before applying a new
version that adds, removes or renames entities.

Without any profile, a device still works with default entities (03 section 9.3).

### 4.3 Field mapping

Profile documents in 03 section 9.2 use snake_case names; lexicon records use
camelCase. The fields map one to one:

| 03 profile document | Lexicon record |
|---|---|
| `profile` | `profile` |
| (none) | `profileVersion` |
| `name`, `manufacturer`, `model`, `power` | same |
| `heartbeat_minutes` | `heartbeatMinutes` |
| `channels[].device_class` | `channels[].deviceClass` |
| `channels[].scale` (number) | `channels[].scale` (decimal string, for example `"0.01"`) |
| `channels[]` other fields | same |
| `commands[]` | `commands[]` |
| (none) | `createdAt` |

## 5. Trust

### 5.1 Local lists

A server keeps local lists, keyed by Nostr public key (09 section 3):

| List | Effect |
|---|---|
| Downlink allow list | If not empty, only these subscribers may request downlinks through this home's proxies (09 section 7, item 6) |
| Block list | Events from these keys are ignored in every direction |

These lists are local settings and need no network.

### 5.2 Published trust

A user MAY publish `org.connectsensors.trust` records to share their choices, for
example so neighbors can follow a well-run neighborhood's decisions:

| `action` | Meaning |
|---|---|
| `allowDownlinks` | The author lets the subject request downlinks |
| `block` | The author blocks the subject |
| `profileSource` | The author uses the subject DID as a profile source |

The subject is a DID (`subjectDid`) or a Nostr key (`subjectPubkey`); exactly one
MUST be present. A server MAY offer to import another user's published trust
records into its own local lists. It MUST NOT apply them automatically.

## 6. Coverage statements

A home that publishes frames (09 section 5) MAY also publish an
`org.connectsensors.coverage` record, so that people nearby can see that
coverage exists and which relays to use to share it.

- `geohash` MUST have at most 5 characters (about 5 km by 5 km). Servers MUST NOT
  offer more precision.
- `relays` lists the relays the publisher uses.
- The record states only that coverage exists. It MUST NOT include device counts,
  signal levels or traffic statistics.
- A server MUST remove the record when the user turns publishing off.

Anyone MAY build a map from these records; that service is outside this
specification.

## 7. Identity links

A link between a DID and a Nostr federation key lets other users recognize a
publisher by its handle rather than by a hex key. A link is valid only if it is
stated in both directions:

1. **DID to key:** an `org.connectsensors.coverage` record (or any record of these
   lexicons naming the key) in the DID's repository, with the key in
   `nostrPubkey`.
2. **Key to DID:** a Nostr event of kind 30078 (NIP-78 application data), signed by
   the key, with tag `["d", "connectsensors:identity"]` and content
   `{"did": "<DID>"}`.

A server MUST show a key's DID handle only when both directions verify, and SHOULD
re-check links at least daily. Either side can end the link by deleting its
statement.

## 8. Security and privacy

| Concern | Handling |
|---|---|
| A malicious profile | Profiles are data, validated against the lexicon. The worst a bad profile can do is mislabel entities. Users choose their profile sources, and see changes before they apply. |
| A compromised profile source | Version changes that alter entities need user approval (4.2). Remove the source to stop further changes. |
| Revealing where someone lives | Coverage records are opt-in and limited to about 5 km. Identity links are opt-in. |
| Revealing who trusts whom | Published trust records are public. Users who want privacy keep their lists local. |
| Spoofed identity links | Links count only when both sides verify (section 7). |

## 9. Lexicons

The lexicon documents are in `lexicons/`:

- `org.connectsensors.deviceProfile.json`
- `org.connectsensors.trust.json`
- `org.connectsensors.coverage.json`

They are licensed like the code and test vectors (`LICENSE-CODE`), so implementations can include them.
