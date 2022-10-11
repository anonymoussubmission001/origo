import { VerifiableCredential } from "@gitcoinco/passport-sdk-types";
import { Passport, Stamp, DID } from "@gitcoinco/passport-sdk-types";

export type CeramicStreamId = string;

export type CeramicStamp = {
  provider: string;
  credential: string;
};

export type CeramicPassport = {
  issuanceDate: string;
  expiryDate: string;
  stamps: CeramicStamp[];
};

export type ModelDefinition = {
  schemas: {
    Passport: string;
    VerifiableCredential: string;
  };
  definitions: {
    Passport: string;
    VerifiableCredential: string;
  };
  tiles: {
    [key: string]: string;
  };
};

export type ModelTypes = {
  schemas: {
    Passport: CeramicPassport;
    VerifiableCredential: VerifiableCredential;
  };
  definitions: {
    Passport: "Passport";
    VerifiableCredential: "VerifiableCredential";
  };
  tiles: Record<string, string>;
};

export type Logger = {
  error: (msg: string, context?: object) => void;
  log: (msg: string, context?: object) => void;
  warn: (msg: string, context?: object) => void;
  debug: (msg: string, context?: object) => void;
  info: (msg: string, context?: object) => void;
};

// Class used as a base for each DataStorage Type
// Implementations should enforce 1 Passport <-> 1 user
//  and it is assumed which Passport/user to act on when
//  calling createPassport, getPassport, addStamp
// export abstract class DataStorageBase {
//   abstract createPassport(): Promise<DID>;
//   abstract getPassport(): Promise<Passport | undefined | false>;
//   abstract addStamp(stamp: Stamp): Promise<void>;
// }


// -- Ceramic and Glazed
import type { CeramicApi } from "@ceramicnetwork/common";
import type { DID as CeramicDID } from "dids";

import { CeramicClient } from "@ceramicnetwork/http-client";
import { DataModel } from "@glazed/datamodel";
import { DIDDataStore } from "@glazed/did-datastore";
import { TileLoader } from "@glazed/tile-loader";
import { StreamID } from "@ceramicnetwork/streamid";

// -- Types
// import type { DID, Passport, Stamp } from "@gitcoinco/passport-sdk-types";
// import type {
//   CeramicStreamId,
//   CeramicPassport,
//   CeramicStamp,
//   DataStorageBase,
//   ModelDefinition,
//   ModelTypes,
//   Logger,
// } from "./types";

// -- Published Models on mainnet and testnet
import TESTNET_PASSPORT_MODEL from "./passportModel.testnet.json";
import MAINNET_PASSPORT_MODEL from "./passportModel.mainnet.json";

// export const MAINNET_PASSPORT_MODEL = {"definitions":{"Passport":"kjzl6cwe1jw145znqlxwwar1crvgsm3wf56vcnxo6bu87fqsi6519eypjnzs7mu","VerifiableCredential":"kjzl6cwe1jw149zuvayqa89nhmlvwm0pkdkj0awlxhmtbbay6i972xuwy14jg4f"},"schemas":{"Passport":"ceramic://k3y52l7qbv1fryatc5h4xpnusk6vw8pmle6duu11djx2dke2senbiecu1fw1wrif4","VerifiableCredential":"ceramic://k3y52l7qbv1fry8pdl0tpicir0jxfwktanqceca89gsvy9geg7o2cd4b6hdr33uv4"},"tiles":{}}
// export const TESTNET_PASSPORT_MODEL = {"definitions":{"Passport":"kjzl6cwe1jw148h1e14jb5fkf55xmqhmyorp29r9cq356c7ou74ulowf8czjlzs","VerifiableCredential":"kjzl6cwe1jw14as2rdgtkfydxiqafbt7db3sld1t90hafem09omybsropfquar0"},"schemas":{"Passport":"ceramic://k3y52l7qbv1frydjk40z9wgf1snwf6axdpc32svgu2jpxrmptldj8rroq2n6a2a68","VerifiableCredential":"ceramic://k3y52l7qbv1frynp3s4v5z0a9wrolxl7kjmbvj19jl9mck442dbtbnwqes5irx3pc"},"tiles":{}}

// Ceramic Testnet URL - must use with testnet passportModel
export const CERAMIC_CLIENT_TESTNET_URL = "https://ceramic-clay.3boxlabs.com";
// Ceramic Mainnet URL - must use with mainnet passportModel
export const CERAMIC_CLIENT_MAINNET_URL = "https://ceramic.passport-iam.gitcoin.co";

// get the passportModel to read/write to and feed it into the PassportWriter along
// with the matching host url (PassportWriter defaults to using testnet)
export const getPassportModel = (network: "mainnet" | "testnet"): ModelDefinition =>
  network === "mainnet" ? MAINNET_PASSPORT_MODEL : TESTNET_PASSPORT_MODEL;

// --- Define an implentation of the DataStorageBase to read/write to Ceramic
// export class PassportWriter implements DataStorageBase {
export default class PassportWriter {
    //_tulons: Tulons;
    //_ceramic_gitcoin_passport_stream_id: string;
    
    did: DID;
    loader: TileLoader;
    ceramicClient: CeramicApi;
    model: DataModel<ModelTypes>;
    store: DIDDataStore<ModelTypes>;
    logger: Logger;

    constructor(did?: CeramicDID, ceramicHost?: string, passportModel?: ModelDefinition, logger?: Logger) {
        if (logger) {
            this.logger = logger;
        } else {
            this.logger = console;
        }

        // create a tulons instance
        // this._tulons = new Tulons(url, network);
        // ceramic definition keys to get streamIds from genesis record
        // this._ceramic_gitcoin_passport_stream_id = "kjzl6cwe1jw148h1e14jb5fkf55xmqhmyorp29r9cq356c7ou74ulowf8czjlzs";
        
        // Create the Ceramic instance and inject the DID
        const ceramic = new CeramicClient(ceramicHost ?? CERAMIC_CLIENT_TESTNET_URL);
            ceramic.setDID(did).catch((e) => {
            console.error(e);
        });

        // Create the loader, model and store
        const loader = new TileLoader({ ceramic });
        const model = new DataModel({ ceramic, aliases: passportModel ?? TESTNET_PASSPORT_MODEL });
        const store = new DIDDataStore({ loader, ceramic, model });

        // Store the users did:pkh (not the session did)
        this.did = (did.hasParent ? did.parent : did.id).toLowerCase();

        // Store state into class
        this.loader = loader;
        this.model = model;
        this.store = store;
        this.ceramicClient = ceramic;
    }

  async createPassport(): Promise<CeramicStreamId> {
    this.logger.info(`create new passport for did ${this.did}`);
    const date = new Date();
    const newPassport: CeramicPassport = {
      issuanceDate: date.toISOString(),
      expiryDate: date.toISOString(),
      stamps: [],
    };
    const stream = await this.store.set("Passport", { ...newPassport });
    return stream.toUrl();
  }

  async getPassport(): Promise<Passport | undefined | false> {
    try {
      const passport = await this.store.get("Passport");
      const streamIDs: string[] = passport?.stamps.map((ceramicStamp: CeramicStamp) => {
        return ceramicStamp.credential;
      });

      this.logger.info(`loaded passport for did ${this.did} => ${JSON.stringify(passport)}`);
      if (!passport) return false;

      // `stamps` is stored as ceramic URLs - must load actual VC data from URL
      const stampsToLoad =
        passport?.stamps.map(async (_stamp) => {
          const { provider, credential } = _stamp;
          try {
            const loadedCred = await this.loader.load(credential);
            return {
              provider,
              credential: loadedCred.content,
              streamId: credential,
            } as Stamp;
          } catch (e) {
            this.logger.error(
              `Error when loading stamp with streamId ${credential} for did  ${this.did}:  ${JSON.stringify(e)}`
            );
            return null;
          }
        }) ?? [];

      const loadedStamps = await Promise.all(stampsToLoad);

      const parsePassport: Passport = {
        issuanceDate: new Date(passport.issuanceDate),
        expiryDate: new Date(passport.expiryDate),
        stamps: loadedStamps,
      };

      // try pinning passport
      try {
        const passportDoc = await this.store.getRecordDocument(this.model.getDefinitionID("Passport"));
        await this.ceramicClient.pin.add(passportDoc.id);
      } catch (e) {
        this.logger.error(`Error when pinning passport for did  ${this.did}: ${JSON.stringify(e)}`);
      }

      return parsePassport;
    } catch (e) {
      this.logger.error(`Error when loading passport for did  ${this.did}: ${JSON.stringify(e)}`);
      return undefined;
    }
  }

  async addStamp(stamp: Stamp): Promise<void> {
    // get passport document from user did data store in ceramic
    const passport = await this.store.get("Passport");
    this.logger.info("adding stamp:", passport)

    // ensure the users did matches the credentials subject id otherwise skip the save
    if (passport && this.did === stamp.credential.credentialSubject.id.toLowerCase()) {
      // create a tile for verifiable credential issued from iam server
      const newStampTile = await this.model.createTile("VerifiableCredential", stamp.credential);

      // add stamp provider and streamId to passport stamps array
      const newStamps = passport?.stamps.concat({ provider: stamp.provider, credential: newStampTile.id.toUrl() });

      // merge new stamps array to update stamps on the passport
      const streamId = await this.store.merge("Passport", { stamps: newStamps });

      // try pinning passport
      try {
        await this.ceramicClient.pin.add(streamId);
      } catch (e) {
        this.logger.error(`Error when pinning passport for did  ${this.did}:  ${JSON.stringify(e)}`);
      }
    }
  }

  async deleteStamp(streamId: string): Promise<void> {
    // get passport document from user did data store in ceramic
    const passport = await this.store.get("Passport");

    if (passport && passport.stamps) {
      const itemIndex = passport.stamps.findIndex((stamp) => {
        return stamp.credential === streamId;
      });

      if (itemIndex != -1) {
        // Remove the stamp from the stamp list
        passport.stamps.splice(itemIndex, 1);

        // merge new stamps array to update stamps on the passport
        const passportStreamId = await this.store.merge("Passport", { stamps: passport.stamps });

        // try to unpin the stamp
        const stampStreamId: StreamID = StreamID.fromString(streamId);
        try {
          await this.ceramicClient.pin.rm(stampStreamId);
        } catch (e) {
          this.logger.error(
            `Error when unpinning stamp with id ${stampStreamId.toString()} for did  ${this.did}: ${JSON.stringify(e)}`
          );
        }

        // try pinning passport
        try {
          await this.ceramicClient.pin.add(passportStreamId);
        } catch (e) {
          this.logger.error(`Error when pinning passport for did  ${this.did}:  ${JSON.stringify(e)}`);
        }
      } else {
        this.logger.info(`unable to find stamp with stream id ${streamId} in passport`);
      }
    }
  }

  async deletePassport(): Promise<void> {
    this.logger.info(`deleting passport for did ${this.did}`);
    // Created for development purposes
    await this.store.remove("Passport");
  }
}

