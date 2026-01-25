# Music Player Application Design

## Overview

A browser-based music player application built on the reeeductio spaces API, enabling users to listen to their purchased music files from anywhere with end-to-end encryption and cross-device synchronization.

## Architecture

### Storage Backend
- **Primary storage**: reeeductio space encrypted key-value store
- **Blob storage**: S3 with presigned URLs supporting HTTP range requests

### Scale
- **Target library size**: ~10,000 tracks
- **Access pattern**: Personal use (single user)
- **Playback mode**: Streaming only (download-then-play)
- **Future features**: "Now playing" activity feed, potential social features

## Space Structure

### Single Space Approach

Using a single space for the entire music library provides:
- Simplified key management (one encryption key)
- Unified access control
- Better performance (no cross-space queries)
- Easier sharing capabilities for future features

```
Personal Music Space (C_...)
│
├── /library/
│   ├── index                              # Lightweight searchable index
│   ├── tracks/{track_id}                  # Full track metadata + blob IDs
│   ├── albums/{album_id}                  # Album metadata + artwork blob ID
│   └── artists/{artist_id}                # Artist metadata
│
├── /user/{user_id}/
│   ├── playlists/{playlist_id}            # User playlists
│   ├── favorites                          # Favorited track IDs
│   ├── recently_played                    # Play history (ring buffer)
│   ├── queue                              # Current play queue
│   ├── playback_state                     # Current position, volume, etc.
│   └── preferences/cache                  # Cache settings
│
├── /topics/
│   └── nowplaying/messages                # "Now playing" activity feed
│
└── /blobs/
    └── {blob_id}                          # Encrypted audio + artwork
```

## Data Models

### Track ID Generation

Track IDs are generated deterministically using a pseudorandom function (PRF) of the original audio file:

```typescript
// Derive PRF key from space's symmetric key
async function derivePRFKey(spaceSymmetricKey: Uint8Array): Promise<CryptoKey> {
  const prfKeyMaterial = await crypto.subtle.importKey(
    'raw',
    spaceSymmetricKey,
    'HKDF',
    false,
    ['deriveBits', 'deriveKey']
  );

  const prfKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('reeeductio-music-track-id'),
      info: new TextEncoder().encode('v1')
    },
    prfKeyMaterial,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return prfKey;
}

// Generate deterministic track ID from entire file
async function generateTrackId(
  audioFileBytes: ArrayBuffer,
  spaceSymmetricKey: Uint8Array
): Promise<string> {
  // 1. Hash the entire file (including ID3 tags, container metadata, everything)
  const fileHash = await crypto.subtle.digest('SHA-256', audioFileBytes);

  // 2. Get PRF key derived from space key
  const prfKey = await derivePRFKey(spaceSymmetricKey);

  // 3. Apply PRF: HMAC-SHA256(prfKey, fileHash)
  const prfOutput = await crypto.subtle.sign('HMAC', prfKey, fileHash);

  // 4. Encode as track_id (128 bits for collision resistance)
  const trackIdBytes = new Uint8Array(prfOutput).slice(0, 16);
  return `track_${base64urlEncode(trackIdBytes)}`;
}
```

**Benefits:**

- ✅ **Automatic deduplication** - Same file uploaded twice = same track ID, skip re-upload
- ✅ **Privacy-preserving** - PRF prevents cross-space linkability (different spaces get different IDs for same file)
- ✅ **Deterministic** - Reproducible across devices given same file and space key
- ✅ **Simple** - No format parsing needed, just hash entire file
- ✅ **Collision-resistant** - 128-bit IDs provide ~2^64 tracks before 50% collision probability

**Implications:**

- Same file byte-for-byte → Same track ID (deduplication works)
- Different metadata in ID3 tags → Different track ID (rare for purchased files)
- Different encoding (320kbps vs 128kbps) → Different track IDs (likely desired)

**Metadata updates:**

If you need to fix metadata without re-uploading:

```typescript
// Update metadata in place
const trackId = await generateTrackId(originalFileBytes, spaceKey);
const existing = await musicSpace.getState(`library/tracks/${trackId}`);
const updated = { ...existing, title: "Fixed Typo" };
await musicSpace.setEncryptedState(`library/tracks/${trackId}`, updated);
// No need to re-upload blob!
```

### Artist and Album ID Generation

Artist and album IDs use the same PRF approach for consistency:

```typescript
// Generate artist ID from artist name
async function generateArtistId(
  artistName: string,
  spaceSymmetricKey: Uint8Array
): Promise<string> {
  // 1. Hash the artist name
  const nameBytes = new TextEncoder().encode(artistName.trim().toLowerCase());
  const nameHash = await crypto.subtle.digest('SHA-256', nameBytes);

  // 2. Get PRF key (same derivation as tracks)
  const prfKey = await derivePRFKey(spaceSymmetricKey);

  // 3. Apply PRF
  const prfOutput = await crypto.subtle.sign('HMAC', prfKey, nameHash);

  // 4. Encode as artist_id (128 bits)
  const artistIdBytes = new Uint8Array(prfOutput).slice(0, 16);
  return `artist_${base64urlEncode(artistIdBytes)}`;
}

// Generate album ID from artist name + album name
async function generateAlbumId(
  artistName: string,
  albumName: string,
  spaceSymmetricKey: Uint8Array
): Promise<string> {
  // 1. Hash the combined artist + album name
  const combined = `${artistName.trim().toLowerCase()}|${albumName.trim().toLowerCase()}`;
  const combinedBytes = new TextEncoder().encode(combined);
  const combinedHash = await crypto.subtle.digest('SHA-256', combinedBytes);

  // 2. Get PRF key (same derivation as tracks)
  const prfKey = await derivePRFKey(spaceSymmetricKey);

  // 3. Apply PRF
  const prfOutput = await crypto.subtle.sign('HMAC', prfKey, combinedHash);

  // 4. Encode as album_id (128 bits)
  const albumIdBytes = new Uint8Array(prfOutput).slice(0, 16);
  return `album_${base64urlEncode(albumIdBytes)}`;
}
```

**Normalization strategy:**
- Convert to lowercase (case-insensitive matching)
- Trim whitespace
- "The Beatles" = "the beatles" for ID generation
- Ensures consistent IDs regardless of capitalization variations

**Benefits:**
- ✅ **Consistent IDs** - Same artist/album name always gets same ID
- ✅ **Privacy-preserving** - PRF prevents cross-space linkability
- ✅ **Automatic grouping** - All tracks by same artist share artist_id
- ✅ **Deduplication** - Albums with same name+artist are merged

**Album ID includes artist:**
- Prevents collision: "Greatest Hits" by different artists → different album IDs
- Natural grouping: All tracks from "Abbey Road" by "The Beatles" → same album_id

### Track Metadata (Hybrid Approach)

Denormalized for fast display, with IDs for rich data lookup:

```json
{
  "track_id": "track_001",
  "title": "Come Together",

  "artist_name": "The Beatles",
  "album_name": "Abbey Road",
  "album_year": 1969,

  "artist_id": "artist_001",
  "album_id": "album_001",

  "audio_blob_id": "B_...",
  "artwork_blob_id": "B_...",

  "duration_ms": 259000,
  "track_number": 1,
  "disc_number": 1,
  "genre": "Rock",

  "file_format": "mp3",
  "bitrate": 320,

  "encryption": {
    "method": "file",
    "key": "base64_encoded_random_key"
  },

  "purchased_from": "iTunes",
  "purchase_date": "2024-01-15",
  "added_at": 1705334400000
}
```

**Benefits:**
- Single fetch for display (artist/album names embedded)
- Optional rich data via artist_id/album_id lookup
- Fast search and filtering
- Foundation for future artist/album pages

### Album Metadata

Stored at `/library/albums/{album_id}` where `album_id = PRF(artist_name + album_name)`:

```json
{
  "album_id": "album_abc123xyz",
  "title": "Abbey Road",
  "artist_id": "artist_def456uvw",
  "artist_name": "The Beatles",
  "year": 1969,
  "artwork_blob_id": "B_...",
  "artwork_encryption": {
    "method": "file",
    "key": "base64_encoded_key"
  },
  "total_tracks": 17,
  "genre": "Rock",
  "track_ids": ["track_001", "track_002", ...]
}
```

**Note:** Album artwork is shared across all tracks on the album (single blob, referenced by all tracks).

### Artist Metadata

Stored at `/library/artists/{artist_id}` where `artist_id = PRF(artist_name)`:

```json
{
  "artist_id": "artist_def456uvw",
  "name": "The Beatles",
  "bio": "Legendary British rock band...",
  "photo_blob_id": "B_...",
  "formed_year": 1960,
  "genres": ["Rock", "Pop"],
  "album_ids": ["album_abc123xyz", "album_ghi789rst", ...]
}
```

### Search Index

Lightweight index for fast client-side search (~1-2MB for 10K tracks):

```json
{
  "tracks": [
    {
      "id": "track_001",
      "title": "Song Name",
      "artist": "Artist Name",
      "album": "Album Name",
      "duration_ms": 245000
    }
  ],
  "last_updated": 1705334400000
}
```

**Search Strategy:**
1. Fetch index on app load (single state read)
2. Perform client-side filtering/sorting (fast for 10K records)
3. Lazy-load full metadata on demand when playing/viewing

**Alternative for larger libraries:**
- Split by first letter: `/library/index/A`, `/library/index/B`, etc.
- Fetch indices on-demand as user types

### Playlist

```json
{
  "playlist_id": "morning_jams",
  "name": "Morning Jams",
  "description": "Wake up music",
  "track_ids": ["track_abc123", "track_def456", "track_ghi789"],
  "created_at": 1705334400000,
  "updated_at": 1705420800000,
  "artwork_blob_id": "B_..."
}
```

### Queue State

```json
{
  "track_ids": ["track_001", "track_002", "track_003"],
  "current_index": 0,
  "shuffle_enabled": false,
  "repeat_mode": "none",
  "updated_at": 1705420800000
}
```

### Playback State

```json
{
  "current_track_id": "track_001",
  "position_ms": 45000,
  "is_playing": true,
  "volume": 0.8,
  "updated_at": 1705420800000
}
```

### "Now Playing" Message

Posted to topic chain for activity tracking:

```json
{
  "type": "now_playing",
  "track_id": "track_abc123",
  "track_title": "Song Name",
  "artist": "Artist Name",
  "album": "Album Name",
  "started_at": 1705420800000,
  "artwork_blob_id": "B_..."
}
```

**Use Cases:**
- Personal listening history timeline
- Analytics ("most played" stats)
- "On this day" memories
- Future: social features (share with friends)

## Playback Architecture

### File-Level Encryption + Download-Then-Play

We use **file-level encryption** (not chunk-level) for simplicity:

**Encryption (during import):**
```typescript
// Generate random data encryption key (DEK) for this specific blob
const dataKey = crypto.getRandomValues(new Uint8Array(32)); // 256-bit AES key
const iv = crypto.getRandomValues(new Uint8Array(16)); // 128-bit IV for AES-GCM

// Import DEK as CryptoKey
const cryptoKey = await crypto.subtle.importKey(
  'raw',
  dataKey,
  { name: 'AES-GCM' },
  true,
  ['encrypt', 'decrypt']
);

// Encrypt audio file with random DEK
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  cryptoKey,
  audioFileBytes
);

// Prepend IV to ciphertext (self-contained blob)
// Format: [16-byte IV][ciphertext with appended GCM auth tag]
const encryptedBlob = new Uint8Array(16 + ciphertext.byteLength);
encryptedBlob.set(new Uint8Array(iv), 0);
encryptedBlob.set(new Uint8Array(ciphertext), 16);

// Upload encrypted blob (IV + ciphertext + auth tag) to S3
await uploadBlob(audioBlobId, encryptedBlob.buffer);

// Store only DEK in track metadata (IV is with the blob)
trackMetadata.encryption = {
  method: 'file',
  key: base64(dataKey)  // Random per-blob key
};

// Save metadata to space (entire metadata object gets encrypted)
await musicSpace.setEncryptedState(`library/tracks/${trackId}`, trackMetadata);
```

**Blob format:**
- Bytes 0-15: Random IV (initialization vector)
- Bytes 16-N: AES-GCM ciphertext with authentication tag appended by Web Crypto API
- The IV is stored with the ciphertext, making blobs self-contained

**Security model:**
- Each blob has a unique random encryption key (DEK - Data Encryption Key)
- DEK is stored in the track metadata
- Track metadata is encrypted by the reeeductio space (using space's symmetric key)
- Result: Two layers of encryption - blob encrypted with DEK, DEK encrypted in space state
- Benefit: Compromising one track's key doesn't expose other tracks

**Playback (simple Blob URL approach):**

1. **Fetch track metadata** from space state (decrypted by SDK)
2. **Download encrypted blob** from S3
3. **Decrypt blob** using DEK from metadata
4. **Create Blob URL** from decrypted ArrayBuffer
5. **Play** via HTML5 Audio element
6. **Pre-fetch next track** in background during playback

**Code example:**
```typescript
async playTrack(trackId: string) {
  // 1. Get track metadata (SDK decrypts state automatically)
  const metadataEntry = await musicSpace.getState(`library/tracks/${trackId}`);
  const metadata = JSON.parse(base64decode(metadataEntry.data));

  // 2. Check cache first
  let decryptedAudio = await cacheDB.getTrack(trackId);

  if (!decryptedAudio) {
    // 3. Download encrypted blob (contains IV + ciphertext + auth tag)
    const encryptedBlob = await musicSpace.downloadBlob(metadata.audio_blob_id);

    // 4. Extract IV from first 16 bytes
    const blobBytes = new Uint8Array(encryptedBlob);
    const iv = blobBytes.slice(0, 16);
    const ciphertext = blobBytes.slice(16);

    // 5. Import DEK from metadata
    const dataKey = base64decode(metadata.encryption.key);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      dataKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // 6. Decrypt with blob's specific DEK and extracted IV
    decryptedAudio = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      ciphertext
    );

    // 7. Cache decrypted audio
    await cacheDB.cacheTrack(trackId, decryptedAudio, metadata);
  }

  // 8. Create Blob URL and play
  const blob = new Blob([decryptedAudio], { type: `audio/${metadata.file_format}` });
  const url = URL.createObjectURL(blob);

  this.audio = new Audio(url);
  this.audio.play();

  // 9. Cleanup when done
  this.audio.addEventListener('ended', () => {
    URL.revokeObjectURL(url);
  });
}
```

**Why file-level encryption?**
- ✅ Simple implementation (no complex chunking logic)
- ✅ Works with all audio formats (MP3, AAC/M4A, FLAC, Opus)
- ✅ No external libraries needed (mp4box.js, etc.)
- ✅ Pre-fetching + caching make latency negligible
- ✅ Decryption overhead is minimal (~100-500ms)

**Timeline:**
- User clicks play → Download starts (~5-10 seconds for typical track)
- Download completes → Decrypt (~100-500ms) → Play starts
- Current track starts playing → Next track download begins
- Track ends → Next track plays instantly (already cached and decrypted)

### Pre-fetching Strategy

```typescript
// Basic strategy
onTrackStart(currentTrack) {
  downloadAndCacheNextTrack();
}

// Advanced strategy (bandwidth-aware)
if (connectionSpeed === '4g') {
  prefetchNext3Tracks();
} else {
  prefetchNext1Track();
}

// Halfway checkpoint
onTrackHalfway(currentTrack) {
  if (!isNextTrackCached()) {
    priorityPrefetchNextTrack();
  }
}
```

### Caching Layer: IndexedDB

**Why IndexedDB over in-memory:**
- Persists across browser sessions
- Larger storage quota (~50GB+ typical)
- Instant playback for recently played tracks
- Automatic LRU eviction when full

**Cache Schema:**

```typescript
interface CachedTrack {
  trackId: string;
  audioData: ArrayBuffer;          // Decrypted audio bytes
  metadata: {
    title: string;
    artist_name: string;
    album_name: string;
    duration_ms: number;
  };
  cachedAt: number;                 // When cached
  lastAccessed: number;             // For LRU eviction
  size: number;                     // Bytes
}
```

**Indices:**
- Primary key: `trackId`
- `cachedAt`: For age-based pruning
- `lastAccessed`: For LRU eviction
- `size`: For size calculations

**Cache Management:**
- **Max size**: 2GB default (~200-400 songs at 5-10MB each)
- **Max age**: 30 days default
- **Eviction**: LRU when size limit reached
- **Pruning**: Automatic on app start and after caching

**Storage Quota:**
- Request persistent storage permission
- Monitor quota usage via Storage API
- Warn user if approaching limits

### Playback Flow

```
User clicks "Play Album"
  ↓
Queue set to all album tracks, synced to space state
  ↓
Track 1 download starts (loading indicator shown)
  ↓ (3-8 seconds)
Track 1 decrypted and plays
  ↓
Track 2 prefetch starts in background
  ↓
User enjoys Track 1
  ↓
Track 1 ends → Track 2 plays INSTANTLY (from cache)
  ↓
Track 3 prefetch starts
  ↓
Seamless playback continues through album
```

### Multi-Device Sync

Queue and playback state stored in space:
- Play on phone → queue/position syncs to laptop
- Pause on laptop → phone sees updated position
- Add to queue on any device → all devices updated

## Import Workflow

### Manual Upload Process

User purchases music from iTunes, Amazon Music, etc., then imports:

```typescript
async function importTrack(audioFile: File, spaceSymmetricKey: Uint8Array) {
  // 1. Read audio file bytes
  const audioFileBytes = await audioFile.arrayBuffer();

  // 2. Generate deterministic track ID from file content
  const trackId = await generateTrackId(audioFileBytes, spaceSymmetricKey);

  // 3. Check if track already exists (deduplication)
  const existing = await musicSpace.getState(`library/tracks/${trackId}`);
  if (existing) {
    console.log(`Track already exists (ID: ${trackId}), skipping upload`);
    return { trackId, skipped: true };
  }

  // 4. Parse metadata from file (ID3 tags)
  const metadata = await parseAudioMetadata(audioFile);

  // 5. Generate artist and album IDs
  const artistId = await generateArtistId(metadata.artist, spaceSymmetricKey);
  const albumId = await generateAlbumId(metadata.artist, metadata.album, spaceSymmetricKey);

  // 6. Encrypt audio file with random DEK

  const audioDataKey = crypto.getRandomValues(new Uint8Array(32));
  const audioIV = crypto.getRandomValues(new Uint8Array(16));

  const audioCryptoKey = await crypto.subtle.importKey(
    'raw',
    audioDataKey,
    { name: 'AES-GCM' },
    true,
    ['encrypt']
  );

  const audioCiphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: audioIV },
    audioCryptoKey,
    audioFileBytes
  );

  // Prepend IV to ciphertext
  const encryptedAudio = new Uint8Array(16 + audioCiphertext.byteLength);
  encryptedAudio.set(new Uint8Array(audioIV), 0);
  encryptedAudio.set(new Uint8Array(audioCiphertext), 16);

  // 7. Upload encrypted blob (IV + ciphertext + auth tag) to S3
  const audioBlobId = await uploadBlob(encryptedAudio.buffer);

  // 8. Handle album artwork (also with random DEK)
  const artwork = metadata.artwork || await fetchArtworkFromAPI(metadata);
  const artworkBytes = await artwork.arrayBuffer();

  const artworkDataKey = crypto.getRandomValues(new Uint8Array(32));
  const artworkIV = crypto.getRandomValues(new Uint8Array(16));

  const artworkCryptoKey = await crypto.subtle.importKey(
    'raw',
    artworkDataKey,
    { name: 'AES-GCM' },
    true,
    ['encrypt']
  );

  const artworkCiphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: artworkIV },
    artworkCryptoKey,
    artworkBytes
  );

  // Prepend IV to ciphertext
  const encryptedArtwork = new Uint8Array(16 + artworkCiphertext.byteLength);
  encryptedArtwork.set(new Uint8Array(artworkIV), 0);
  encryptedArtwork.set(new Uint8Array(artworkCiphertext), 16);

  const artworkBlobId = await uploadBlob(encryptedArtwork.buffer);

  // 9. Create track metadata (includes DEKs and IDs)
  const trackMetadata = {
    track_id: trackId,
    title: metadata.title,
    artist_name: metadata.artist,
    artist_id: artistId,
    album_name: metadata.album,
    album_id: albumId,
    audio_blob_id: audioBlobId,
    artwork_blob_id: artworkBlobId,
    duration_ms: metadata.duration,
    track_number: metadata.track_number,
    disc_number: metadata.disc_number || 1,
    file_format: metadata.format,
    bitrate: metadata.bitrate,
    genre: metadata.genre,
    encryption: {
      method: 'file',
      key: base64(audioDataKey)
    },
    artwork_encryption: {
      method: 'file',
      key: base64(artworkDataKey)
    },
    purchased_from: "iTunes",
    added_at: Date.now()
  };

  // 10. Save to space state (metadata gets encrypted by space)
  await musicSpace.setEncryptedState(`library/tracks/${trackId}`, trackMetadata);

  // 11. Update search index
  await updateSearchIndex(trackMetadata);

  // 12. Create/update album entry
  await upsertAlbum({
    album_id: albumId,
    title: metadata.album,
    artist_id: artistId,
    artist_name: metadata.artist,
    year: metadata.year,
    artwork_blob_id: artworkBlobId,
    artwork_encryption: {
      method: 'file',
      key: base64(artworkDataKey)
    },
    genre: metadata.genre,
    track_ids: [trackId]  // Add track to album, merge if album exists
  }, spaceSymmetricKey);

  // 13. Create/update artist entry
  await upsertArtist({
    artist_id: artistId,
    name: metadata.artist,
    album_ids: [albumId],  // Add album to artist, merge if artist exists
    genres: [metadata.genre].filter(Boolean)
  }, spaceSymmetricKey);

  return { trackId, artistId, albumId, skipped: false };
}
```

### Metadata Enrichment

For tracks missing artwork or with incomplete metadata, optionally fetch from MusicBrainz:

```typescript
async function fetchArtworkFromAPI(
  metadata: { artist: string; album: string; title: string }
): Promise<Blob | null> {
  // 1. Try MusicBrainz + Cover Art Archive (free, no API key)
  try {
    const mbSearch = await fetch(
      `https://musicbrainz.org/ws/2/release/?query=` +
      `artist:"${encodeURIComponent(metadata.artist)}" AND ` +
      `release:"${encodeURIComponent(metadata.album)}"&fmt=json`,
      {
        headers: {
          'User-Agent': 'MusicPlayer/1.0 (your@email.com)' // Required
        }
      }
    );

    // Rate limit: max 1 request/second
    await sleep(1000);

    const mbData = await mbSearch.json();
    const releaseId = mbData.releases?.[0]?.id;

    if (releaseId) {
      // Fetch cover art from Cover Art Archive
      const coverArt = await fetch(
        `https://coverartarchive.org/release/${releaseId}/front-500`
      );

      if (coverArt.ok) {
        return await coverArt.blob();
      }
    }
  } catch (err) {
    console.log('MusicBrainz lookup failed, trying fallback...');
  }

  // 2. Fallback: TheAudioDB (also free, no API key)
  try {
    const audioDbSearch = await fetch(
      `https://www.theaudiodb.com/api/v1/json/2/searchalbum.php?` +
      `s=${encodeURIComponent(metadata.artist)}&` +
      `a=${encodeURIComponent(metadata.album)}`
    );

    const audioDbData = await audioDbSearch.json();
    const artworkUrl = audioDbData.album?.[0]?.strAlbumThumb;

    if (artworkUrl) {
      const artwork = await fetch(artworkUrl);
      return await artwork.blob();
    }
  } catch (err) {
    console.log('TheAudioDB lookup failed');
  }

  // 3. Final fallback: return null (use placeholder in UI)
  return null;
}

// Optionally enrich artist metadata
async function enrichArtistMetadata(artistName: string): Promise<{
  bio?: string;
  formed_year?: number;
  genres?: string[];
  musicbrainz_id?: string;
}> {
  try {
    // MusicBrainz artist lookup
    const mbSearch = await fetch(
      `https://musicbrainz.org/ws/2/artist/?query=` +
      `artist:"${encodeURIComponent(artistName)}"&fmt=json`,
      {
        headers: { 'User-Agent': 'MusicPlayer/1.0 (your@email.com)' }
      }
    );

    await sleep(1000);

    const mbData = await mbSearch.json();
    const artist = mbData.artists?.[0];

    if (!artist) return {};

    // Get additional info from Last.fm (free tier, requires API key)
    const lastfmKey = 'YOUR_LASTFM_API_KEY'; // Optional
    const lastfmData = await fetch(
      `http://ws.audioscrobbler.com/2.0/?method=artist.getinfo&` +
      `artist=${encodeURIComponent(artistName)}&` +
      `api_key=${lastfmKey}&format=json`
    );

    const lastfm = await lastfmData.json();

    return {
      bio: lastfm.artist?.bio?.summary,
      formed_year: artist['life-span']?.begin ?
        parseInt(artist['life-span'].begin.split('-')[0]) : undefined,
      genres: artist.tags?.map((t: any) => t.name),
      musicbrainz_id: artist.id
    };
  } catch (err) {
    console.error('Artist enrichment failed:', err);
    return {};
  }
}
```

**Services used:**

1. **MusicBrainz** (https://musicbrainz.org)
   - Free, open-source music encyclopedia
   - No API key required
   - Rate limit: 1 request/second
   - Must include User-Agent header with contact email

2. **Cover Art Archive** (https://coverartarchive.org)
   - Companion to MusicBrainz
   - Free album artwork
   - No rate limits

3. **TheAudioDB** (https://www.theaudiodb.com)
   - Free fallback for artwork
   - No API key required for basic use

4. **Last.fm** (optional)
   - Artist biographies, tags
   - Free API key required
   - Rate limited

**Best practices:**
- Cache MusicBrainz results to avoid repeated queries
- Respect rate limits (1 req/sec for MusicBrainz)
- Include descriptive User-Agent header
- Gracefully handle missing data
- Store MusicBrainz IDs for future lookups

**Optional: Store external IDs in metadata:**

```json
{
  "track_id": "track_abc123",
  "title": "Come Together",
  "artist_name": "The Beatles",
  "album_name": "Abbey Road",

  "external_ids": {
    "musicbrainz_recording_id": "e026c0ec-...",
    "musicbrainz_release_id": "eca8996a-...",
    "musicbrainz_artist_id": "b10bbbfc-..."
  }
}
```

This enables:
- Re-fetching updated metadata later
- Linking to MusicBrainz for more info
- Portable identifiers across systems

### Batch Import

- Drag & drop folder of MP3s
- Parse metadata in parallel
- Preview table (allow metadata edits)
- Bulk upload with progress bar
- Auto-deduplicate by audio hash
- Optional: Enrich metadata from MusicBrainz for missing artwork

## Wallet Space Integration

### Centralized Key Management

A separate "wallet" space stores credentials for all app spaces:

```
Wallet Space (C_wallet_...)
│
└── /user/{user_id}/
    └── spaces/
        ├── music                          # Music space entry
        ├── photos                         # Future: photos space
        └── documents                      # Future: documents space
```

### Music Space Entry

```json
{
  "space_id": "C_music_abc123...",
  "space_key": "base64_encoded_symmetric_key",
  "name": "My Music Library",
  "app_type": "music_player",
  "created_at": 1705334400000,
  "last_accessed": 1705420800000,
  "metadata": {
    "track_count": 10000,
    "total_size_mb": 45000
  }
}
```

**Security Note:** The `space_key` is encrypted with the user's keypair, so even if someone accesses the wallet space data, they cannot decrypt music space contents without the user's private key.

### App Startup Flow

```typescript
// 1. Authenticate to wallet space
const walletSpace = new Space({
  space_id: WALLET_SPACE_ID,
  keypair: userKeypair,
  base_url: API_URL
});

// 2. Fetch music space credentials
const musicSpaceEntry = await walletSpace.getState(`user/${userId}/spaces/music`);
const { space_id, space_key } = JSON.parse(base64decode(musicSpaceEntry.data));

// 3. Connect to music space
const musicSpace = new Space({
  space_id: space_id,
  keypair: userKeypair,
  base_url: API_URL,
  symmetric_key: space_key
});

// 4. Load library
const index = await musicSpace.getState('library/index');
```

## Permissions Model

### Owner (Full Control)

```typescript
const ownerCaps = [
  { op: "write", path: "library/{...}" },      // Manage library
  { op: "write", path: "auth/{...}" },         // Manage users/roles
  { op: "write", path: "user/{self}/{...}" },  // Own data
  { op: "create", path: "topics/{any}/messages/{...}" }
];
```

### User (Basic Access)

```typescript
const userCaps = [
  { op: "read", path: "library/{...}" },       // Browse library
  { op: "write", path: "user/{self}/{...}" },  // Own playlists/state
  { op: "create", path: "topics/{any}/messages/{...}" }
];
```

### Import Tool (Automated Upload)

```typescript
const importToolCaps = [
  { op: "create", path: "library/tracks/{any}" },
  { op: "create", path: "library/albums/{any}" },
  { op: "create", path: "library/artists/{any}" }
];
```

## Technology Stack

### Required JS/TS SDK

Assuming a reeeductio SDK that provides:

```typescript
// High-level SDK
import { Space, generateKeypair } from 'reeeductio';

// Space management
const space = new Space({
  space_id: "C_...",
  keypair: userKeypair,
  base_url: "https://api.music.example.com",
  symmetric_key: spaceKey
});

// State operations
await space.setEncryptedState(path, data);
const entry = await space.getEncryptedState(path);

// Blob operations
await space.uploadBlob(blobId, encryptedData);
const blob = await space.downloadBlob(blobId);
const presignedUrl = await space.getBlobPresignedUrl(blobId);

// Message operations
await space.postMessage(topicId, encryptedPayload);
const messages = await space.getMessages(topicId, { from, to, limit });

// Crypto utilities
const encrypted = await encryptWithSpaceKey(data, spaceKey);
const decrypted = await decryptWithSpaceKey(encrypted, spaceKey);
```

### Frontend

- **Framework**: React, Vue, or vanilla TS
- **Audio**: HTML5 Audio API + MediaSource API
- **Storage**: IndexedDB for cache
- **State**: React Context or similar for app state
- **UI**: Component library (Material-UI, Chakra, etc.)

### Build Tools

- **Bundler**: Vite or Webpack
- **TypeScript**: Strict mode
- **Linting**: ESLint + Prettier

## Security Considerations

### Layered Encryption Architecture

The music player uses a **two-layer encryption model**:

1. **Blob Layer (Application-level encryption)**
   - Each audio/image blob encrypted with unique random DEK (Data Encryption Key)
   - DEK is 256-bit AES-GCM key generated per-blob
   - DEK stored in track metadata (encrypted by space)
   - IV stored with blob (prepended to ciphertext)
   - Blob format: `[16-byte IV][AES-GCM ciphertext with auth tag]`
   - Blobs uploaded to S3 already encrypted and self-contained

2. **State Layer (Space-level encryption)**
   - Track metadata (including DEKs) encrypted by reeeductio space
   - Uses space's symmetric key
   - SDK handles encryption/decryption transparently
   - IV is NOT stored in metadata (stored with blob instead)

**Security benefits:**
- ✅ S3 server never sees plaintext audio or DEKs
- ✅ reeeductio server never sees plaintext audio (only encrypted metadata)
- ✅ Compromising one track's DEK doesn't expose other tracks
- ✅ Client must have both space key AND metadata access to decrypt audio
- ✅ Defense in depth - two independent encryption layers

### PRF-Based Track IDs

Track IDs use HMAC-SHA256 as a PRF (Pseudorandom Function) instead of plain hashing:

**Without PRF (naive approach):**
```typescript
// BAD: Using plain hash as track ID
const trackId = SHA256(audioFile);  // Deterministic but NOT private
```

**Problems with plain hashing:**
- ❌ **Cross-space linkability** - Same song in different users' spaces = same ID
- ❌ **Public databases** - Adversary could build SHA256(popular_song) → "Song Title" mapping
- ❌ **Privacy leak** - Server can identify what songs you have by comparing hashes

**With PRF (our approach):**
```typescript
// GOOD: Using keyed PRF
const trackId = HMAC-SHA256(space_key, SHA256(audioFile));  // Private AND deterministic
```

**Benefits:**
- ✅ **No cross-space linkability** - Different spaces get different track IDs for same file
- ✅ **Server cannot identify songs** - Would need space key to compute expected IDs
- ✅ **Still deterministic** - Same file in same space always gets same ID
- ✅ **Second-preimage resistant** - Cannot find different file with same ID

### What Server Knows

**reeeductio server:**
- Space IDs (public keys)
- User public keys
- Roles, capabilities, permissions
- Message metadata (timestamps, hashes, chain structure)
- Encrypted track metadata (can't read it)
- Blob IDs referenced by tracks

**S3 server:**
- Encrypted blob data (can't decrypt it)
- Blob sizes
- Access patterns (which blobs downloaded when)

### What Server CANNOT Know

**Neither server can see:**
- Track titles, artists, albums (encrypted in space state)
- Audio file contents (encrypted with per-blob DEKs)
- Album artwork (encrypted with per-blob DEKs)
- User playlists, preferences, playback history (encrypted in space state)
- Per-blob encryption keys (DEKs encrypted in space state)
- Space symmetric encryption key
- User private keys

### Threat Model

**Protected against:**
- ✅ Compromised server (E2E encryption)
- ✅ Privilege escalation (capability signatures)
- ✅ Message tampering (hash chains)
- ✅ State tampering (cryptographic signatures)
- ✅ Replay attacks (challenge expiry)

**NOT protected against:**
- ❌ Network analysis (traffic patterns, timing)
- ❌ Compromised space key (full library access)
- ❌ Compromised user key (impersonation)
- ❌ Malicious space creator (admin rights)

### Key Management

**Critical:** Losing the space key = losing access to all music

**Backup strategies:**
- Store in wallet space (encrypted with user key)
- Export to password manager
- QR code for mobile device backup
- Recovery key mechanism

## Future Enhancements

### Social Features

- Share "now playing" with friends
- Collaborative playlists
- Comments on albums/tracks
- Listening activity feed

### Advanced Playback

- Chunk-level encryption for true streaming
- Offline mode for mobile
- Gapless playback
- Crossfade between tracks
- Equalizer/audio effects

### Library Management

- Smart playlists (auto-generated based on criteria)
- Duplicate detection
- Metadata correction/enrichment
- Integration with MusicBrainz/Last.fm

### Analytics

- Listening statistics
- Most played tracks/artists
- Listening patterns over time
- Year-in-review summaries

### Multi-User

- Invite friends to shared spaces
- Read-only guest access
- Collaborative playlist editing
- Activity streams

## Implementation Phases

### Phase 1: MVP

- [ ] Basic playback (download-then-play)
- [ ] Library browsing with search index
- [ ] Simple playlist management
- [ ] IndexedDB caching
- [ ] Manual import workflow

### Phase 2: Core Features

- [ ] Pre-fetching and seamless queue playback
- [ ] "Now playing" messages
- [ ] Multi-device sync (queue/playback state)
- [ ] Wallet space integration
- [ ] Cache management UI

### Phase 3: Polish

- [ ] Batch import with metadata editing
- [ ] Album/artist pages
- [ ] Advanced search/filtering
- [ ] Keyboard shortcuts
- [ ] Mobile-responsive design

### Phase 4: Advanced

- [ ] Listening analytics
- [ ] Smart playlists
- [ ] Social features
- [ ] Chunk-level encryption for streaming
- [ ] Progressive Web App (PWA)

## Open Questions

1. ~~**Track ID generation**~~: ✅ **Resolved** - Use PRF-based content addressing (HMAC-SHA256 of file hash)
2. ~~**Album/Artist IDs**~~: ✅ **Resolved** - Use PRF(artist_name) for artists, PRF(artist_name + album_name) for albums
3. **Artwork deduplication**: How to handle same album art across different albums (e.g., compilations)? Currently each album stores its own artwork blob.
4. **Metadata editing**: Allow in-place editing after import, or require re-import?
5. **Sync conflicts**: If queue modified on two devices simultaneously, which wins?
6. **Message history limits**: Cap "now playing" messages at N entries to prevent unbounded growth?

## References

### reeeductio

- [reeeductio Spaces API Documentation](../docs/)
- [reeeductio Python SDK](../sdk/python/)

### Web APIs

- [IndexedDB API](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
- [HTML5 Audio](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/audio)
- [Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

### Music Metadata Services

- [MusicBrainz](https://musicbrainz.org) - Open music encyclopedia
- [MusicBrainz API Documentation](https://musicbrainz.org/doc/MusicBrainz_API)
- [Cover Art Archive](https://coverartarchive.org) - Album artwork
- [TheAudioDB](https://www.theaudiodb.com) - Free music database
- [Last.fm API](https://www.last.fm/api) - Artist bios and scrobbling
