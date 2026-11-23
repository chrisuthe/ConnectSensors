# 10 - Control Plane

Status: Draft
Version: 1.0-draft.2

This document specifies the optional, slow-moving information that participants
share: device profiles. It uses AT Protocol records described by the lexicon in
`lexicons/`.

Nothing in 00-09 depends on this document. A home with no internet connection,
or one that never enables these features, works fully.

## 1. Goals (informative)

- A new sensor design works in everyone's Home Assistant as soon as its author
  publishes a profile, with no integration release.

Earlier drafts also carried trust lists, coverage statements and identity links
for federation. Mailbox federation (09) needs none of them: only a device's own
session key holders can request its downlinks, publishers are judged by their
records (09 section 9), and mailbox operators set admission (09 section 11).

## 2. Principles

- **Data only.** Everything here is declarative data. A server MUST validate it
  against the lexicons and MUST NOT execute anything from it.
- **No sensor data.** Readings, frames, timings, device lists and federation
  keys MUST NOT be published through the control plane. Live traffic stays in
  09.
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

## 5. Security and privacy

| Concern | Handling |
|---|---|
| A malicious profile | Profiles are data, validated against the lexicon. The worst a bad profile can do is mislabel entities. Users choose their profile sources, and see changes before they apply. |
| A compromised profile source | Version changes that alter entities need user approval (4.2). Remove the source to stop further changes. |
| Revealing who uses which devices | Reading a profile reveals interest in it to the source's host, as fetching any public record does. Profiles built in or imported as files need no fetch. |

## 6. Lexicons

The lexicon document is `lexicons/org.connectsensors.deviceProfile.json`.
It is licensed like the code and test vectors (`LICENSE-CODE`), so implementations can include it.
