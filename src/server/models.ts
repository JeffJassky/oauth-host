import mongoose from 'mongoose';
import type { Connection, Model, Mongoose, Schema } from 'mongoose';
// Document shapes live in the PUBLISHED declarations, not here. Hosts type
// their own queries against them, so `types/index.d.ts` is the single source of
// truth and the source imports it — not the other way round. See traps #9.
import type {
  ModelNames,
  OAuthAuditDoc,
  OAuthClientDoc,
  OAuthCodeDoc,
  OAuthGrantDoc,
  OAuthKeyDoc,
  OAuthModels,
  OAuthRequestDoc,
  OAuthTokenDoc,
} from '../../types/index.js';

/**
 * Seven collections, one factory each.
 *
 * Mongoose keeps compiled models in a registry on the connection, so calling
 * `connection.model(name, schema)` twice for the same name throws
 * OverwriteModelError. A library cannot own seven global names unconditionally
 * — the host may already have a `Grant`, or the package may be loaded twice
 * through a hoisting mismatch. So: reuse an already-compiled model when the
 * name is taken, and let the host rename any of them via `modelNames`.
 *
 * The tradeoff, which belongs in the docs: if the existing model isn't ours,
 * queries fail confusingly. Tell hosts to set `modelNames` when a collision is
 * plausible. See standards/traps.md #2.
 */

const DEFAULT_NAMES: Required<ModelNames> = {
  client: 'OAuthClient',
  grant: 'OAuthGrant',
  code: 'OAuthCode',
  token: 'OAuthToken',
  request: 'OAuthRequest',
  key: 'OAuthKey',
  audit: 'OAuthAudit',
};

function compile<T>(
  connection: Mongoose | Connection,
  name: string,
  build: () => Schema<T>,
  collection: string,
): Model<T> {
  const existing = connection.models?.[name] as Model<T> | undefined;
  if (existing) return existing;
  // Cast rather than a generic argument: mongoose's `model()` overloads infer
  // a hydrated-document type from the schema, and pinning the doc type through
  // the generic slot fights that inference instead of describing it.
  return connection.model(name, build() as never, collection) as unknown as Model<T>;
}

// ---------------------------------------------------------------------------

function clientSchema(): Schema<OAuthClientDoc> {
  const schema = new mongoose.Schema<OAuthClientDoc>(
    {
      clientId: { type: String, required: true, unique: true },
      name: { type: String, required: true },
      // `public` is a client that holds no secret and is bound by PKCE instead.
      // Two ways in and they are independent: a CIMD row is written public, and
      // `clients.create({ type: 'public' })` registers one by hand. The enum was
      // written with this widening in mind, so it was one member rather than a
      // migration.
      type: { type: String, enum: ['confidential', 'public'], default: 'confidential' },
      // How the row got here. A `cimd` row is re-derived from the client's own
      // metadata document, so this is what tells the re-fetch path which fields
      // it owns — and `status` is deliberately not one of them.
      registration: { type: String, enum: ['manual', 'cimd'], default: 'manual' },
      metadataUrl: String,
      metadataFetchedAt: Date,
      metadataEtag: String,
      trusted: { type: Boolean, default: false },
      // An array, not a string: rotation needs two live secrets at once or it
      // cannot be deployed without downtime.
      secrets: [
        {
          _id: false,
          hash: { type: String, required: true },
          label: String,
          createdAt: { type: Date, default: Date.now },
          lastUsedAt: Date,
          retiresAt: Date,
        },
      ],
      redirectUris: { type: [String], default: [] },
      allowedScopes: { type: [String], default: [] },
      allowedResources: { type: [String], default: [] },
      branding: {
        _id: false,
        logoUrl: String,
        publisher: String,
        homepageUrl: String,
        tosUrl: String,
        privacyUrl: String,
      },
      status: { type: String, enum: ['active', 'disabled'], default: 'active' },
      // Pairwise subjects live on the client, not in a collection of their own:
      // they are per-(client, user) and are read on every token issuance for
      // that client. A Map keyed by user id keeps that a single document read.
      pairwiseSubjects: { type: Map, of: String },
    },
    { timestamps: true },
  );

  return schema;
}

function grantSchema(): Schema<OAuthGrantDoc> {
  const schema = new mongoose.Schema<OAuthGrantDoc>(
    {
      userId: { type: mongoose.Schema.Types.Mixed, required: true },
      clientId: { type: String, required: true },
      // `null`, never absent. A missing field and a null field index
      // differently, and the unique index below has to see one consistent
      // value for single-subject mode.
      contextId: { type: String, default: null },
      scopes: { type: [String], default: [] },
      resources: { type: [String], default: [] },
      version: { type: Number, default: 1 },
      lastUsedAt: Date,
      revokedAt: { type: Date, default: null },
      revokedBy: { type: String, enum: ['user', 'admin', 'system', 'client'] },
    },
    { timestamps: true },
  );

  // One LIVE grant per (client, user, context). Partial on `revokedAt: null`
  // so a revoked grant does not block re-consent — the alternative is either
  // deleting revocation history or hitting a duplicate key on the second
  // connect, and both are worse.
  schema.index(
    { clientId: 1, userId: 1, contextId: 1 },
    { unique: true, partialFilterExpression: { revokedAt: null } },
  );
  schema.index({ userId: 1 });
  schema.index({ clientId: 1 });

  return schema;
}

function codeSchema(): Schema<OAuthCodeDoc> {
  const schema = new mongoose.Schema<OAuthCodeDoc>(
    {
      codeHash: { type: String, required: true, unique: true },
      clientId: { type: String, required: true },
      userId: { type: mongoose.Schema.Types.Mixed, required: true },
      grantId: { type: mongoose.Schema.Types.ObjectId, required: true },
      contextId: { type: String, default: null },
      scopes: { type: [String], default: [] },
      resources: { type: [String], default: [] },
      redirectUri: { type: String, required: true },
      codeChallenge: { type: String, required: true },
      codeChallengeMethod: { type: String, enum: ['S256'], default: 'S256' },
      nonce: String,
      authTime: Date,
      // Set, not deleted, on redemption. A consumed code has to stay readable
      // long enough to detect the replay — see `tokens.ts`.
      consumedAt: { type: Date, default: null },
      expiresAt: { type: Date, required: true },
    },
    { timestamps: { createdAt: true, updatedAt: false } },
  );

  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return schema;
}

function tokenSchema(): Schema<OAuthTokenDoc> {
  const schema = new mongoose.Schema<OAuthTokenDoc>(
    {
      kind: { type: String, enum: ['access', 'refresh'], required: true },
      tokenHash: { type: String, required: true, unique: true },
      clientId: { type: String, required: true },
      userId: { type: mongoose.Schema.Types.Mixed, required: true },
      grantId: { type: mongoose.Schema.Types.ObjectId, required: true },
      contextId: { type: String, default: null },
      scopes: { type: [String], default: [] },
      audience: { type: [String], default: [] },
      familyId: { type: String, required: true },
      parentId: { type: mongoose.Schema.Types.ObjectId, default: null },
      consumedAt: { type: Date, default: null },
      revokedAt: { type: Date, default: null },
      familyExpiresAt: Date,
      expiresAt: { type: Date, required: true },
    },
    { timestamps: { createdAt: true, updatedAt: false } },
  );

  // The TTL reaps expired tokens, which is why `expiresAt` on a refresh token
  // is the SLIDING window and `familyExpiresAt` carries the absolute ceiling:
  // letting Mongo delete the row is only safe if nothing downstream needed it.
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  schema.index({ familyId: 1 });
  schema.index({ grantId: 1 });
  schema.index({ userId: 1, clientId: 1 });

  return schema;
}

function requestSchema(): Schema<OAuthRequestDoc> {
  const schema = new mongoose.Schema<OAuthRequestDoc>(
    {
      requestId: { type: String, required: true, unique: true },
      clientId: { type: String, required: true },
      userId: { type: mongoose.Schema.Types.Mixed, required: true },
      redirectUri: { type: String, required: true },
      scopes: { type: [String], default: [] },
      resources: { type: [String], default: [] },
      state: String,
      nonce: String,
      codeChallenge: { type: String, required: true },
      codeChallengeMethod: { type: String, enum: ['S256'], default: 'S256' },
      prompt: String,
      maxAge: Number,
      decision: { type: String, enum: ['approved', 'denied'] },
      decidedAt: Date,
      expiresAt: { type: Date, required: true },
    },
    { timestamps: { createdAt: true, updatedAt: false } },
  );

  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return schema;
}

function keySchema(): Schema<OAuthKeyDoc> {
  const schema = new mongoose.Schema<OAuthKeyDoc>(
    {
      kid: { type: String, required: true, unique: true },
      alg: { type: String, enum: ['ES256'], default: 'ES256' },
      publicJwk: { type: mongoose.Schema.Types.Mixed, required: true },
      // Retiring keys stay published in JWKS so tokens signed by them still
      // validate; only `active` is used to sign.
      privateJwk: { type: mongoose.Schema.Types.Mixed, required: true },
      status: { type: String, enum: ['active', 'retiring'], default: 'active' },
    },
    { timestamps: { createdAt: true, updatedAt: false } },
  );

  return schema;
}

function auditSchema(retentionDays: number): Schema<OAuthAuditDoc> {
  const schema = new mongoose.Schema<OAuthAuditDoc>(
    {
      type: { type: String, required: true },
      actor: { type: String, enum: ['user', 'client', 'admin', 'system'] },
      clientId: String,
      userId: mongoose.Schema.Types.Mixed,
      grantId: mongoose.Schema.Types.ObjectId,
      ip: String,
      meta: mongoose.Schema.Types.Mixed,
    },
    { timestamps: { createdAt: true, updatedAt: false } },
  );

  // A log nothing prunes is an outage waiting. Not a time-series collection:
  // erasure needs `deleteMany`, and time-series does not support it.
  // See standards/traps.md #17.
  schema.index({ createdAt: 1 }, { expireAfterSeconds: retentionDays * 86_400 });
  schema.index({ clientId: 1, createdAt: -1 });
  schema.index({ userId: 1, createdAt: -1 });

  return schema;
}

// ---------------------------------------------------------------------------

export interface CreateModelsOptions {
  connection?: Mongoose | Connection;
  modelNames?: ModelNames;
  collectionPrefix?: string;
  auditRetentionDays?: number;
}

export function createModels({
  connection = mongoose,
  modelNames = {},
  collectionPrefix = 'oauth_',
  auditRetentionDays = 400,
}: CreateModelsOptions = {}): OAuthModels {
  const names = { ...DEFAULT_NAMES, ...modelNames };
  const c = (suffix: string) => `${collectionPrefix}${suffix}`;

  return {
    Client: compile<OAuthClientDoc>(connection, names.client, clientSchema, c('clients')),
    Grant: compile<OAuthGrantDoc>(connection, names.grant, grantSchema, c('grants')),
    Code: compile<OAuthCodeDoc>(connection, names.code, codeSchema, c('codes')),
    Token: compile<OAuthTokenDoc>(connection, names.token, tokenSchema, c('tokens')),
    Request: compile<OAuthRequestDoc>(connection, names.request, requestSchema, c('requests')),
    Key: compile<OAuthKeyDoc>(connection, names.key, keySchema, c('keys')),
    Audit: compile<OAuthAuditDoc>(
      connection,
      names.audit,
      () => auditSchema(auditRetentionDays),
      c('audit'),
    ),
  };
}

/**
 * Build every index before the first write.
 *
 * Mongoose builds indexes in the background, so a cold database can serve a
 * write before its unique index exists — which is exactly long enough for two
 * grants to be created for one (client, user, context). Await this at boot.
 * See standards/traps.md #3.
 */
export async function syncModelIndexes(models: OAuthModels): Promise<void> {
  await Promise.all(Object.values(models).map((m) => m.init()));
}
