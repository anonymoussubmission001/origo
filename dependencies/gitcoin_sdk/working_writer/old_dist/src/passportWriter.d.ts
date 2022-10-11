import type { CeramicApi } from "@ceramicnetwork/common";
import type { DID as CeramicDID } from "dids";
import { DataModel } from "@glazed/datamodel";
import { DIDDataStore } from "@glazed/did-datastore";
import { TileLoader } from "@glazed/tile-loader";
import type { DID, Passport, Stamp } from "@gitcoinco/passport-sdk-types";
import type { CeramicStreamId, DataStorageBase, ModelDefinition, ModelTypes, Logger } from "./types";
export declare const CERAMIC_CLIENT_TESTNET_URL = "https://ceramic-clay.3boxlabs.com";
export declare const CERAMIC_CLIENT_MAINNET_URL = "https://ceramic.passport-iam.gitcoin.co";
export declare const getPassportModel: (network: "mainnet" | "testnet") => ModelDefinition;
export declare class PassportWriter implements DataStorageBase {
    did: DID;
    loader: TileLoader;
    ceramicClient: CeramicApi;
    model: DataModel<ModelTypes>;
    store: DIDDataStore<ModelTypes>;
    logger: Logger;
    constructor(did?: CeramicDID, ceramicHost?: string, passportModel?: ModelDefinition, logger?: Logger);
    createPassport(): Promise<CeramicStreamId>;
    getPassport(): Promise<Passport | undefined | false>;
    addStamp(stamp: Stamp): Promise<void>;
    deleteStamp(streamId: string): Promise<void>;
    deletePassport(): Promise<void>;
}
