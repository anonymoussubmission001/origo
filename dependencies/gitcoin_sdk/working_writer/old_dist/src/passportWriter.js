/* eslint no-console: ["error", { allow: ["error"] }] */
import { CeramicClient } from "@ceramicnetwork/http-client";
import { DataModel } from "@glazed/datamodel";
import { DIDDataStore } from "@glazed/did-datastore";
import { TileLoader } from "@glazed/tile-loader";
import { StreamID } from "@ceramicnetwork/streamid";
// -- Published Models on mainnet and testnet
import TESTNET_PASSPORT_MODEL from "./passportModel.testnet.json";
import MAINNET_PASSPORT_MODEL from "./passportModel.mainnet.json";
// Ceramic Testnet URL - must use with testnet passportModel
export const CERAMIC_CLIENT_TESTNET_URL = "https://ceramic-clay.3boxlabs.com";
// Ceramic Mainnet URL - must use with mainnet passportModel
export const CERAMIC_CLIENT_MAINNET_URL = "https://ceramic.passport-iam.gitcoin.co";
// get the passportModel to read/write to and feed it into the PassportWriter along
// with the matching host url (PassportWriter defaults to using testnet)
export const getPassportModel = (network) => network === "mainnet" ? MAINNET_PASSPORT_MODEL : TESTNET_PASSPORT_MODEL;
// --- Define an implentation of the DataStorageBase to read/write to Ceramic
export class PassportWriter {
    constructor(did, ceramicHost, passportModel, logger) {
        if (logger) {
            this.logger = logger;
        }
        else {
            this.logger = console;
        }
        // Create the Ceramic instance and inject the DID
        const ceramic = new CeramicClient(ceramicHost !== null && ceramicHost !== void 0 ? ceramicHost : CERAMIC_CLIENT_TESTNET_URL);
        ceramic.setDID(did).catch((e) => {
            console.error(e);
        });
        // Create the loader, model and store
        const loader = new TileLoader({ ceramic });
        const model = new DataModel({ ceramic, aliases: passportModel !== null && passportModel !== void 0 ? passportModel : TESTNET_PASSPORT_MODEL });
        const store = new DIDDataStore({ loader, ceramic, model });
        // Store the users did:pkh (not the session did)
        this.did = (did.hasParent ? did.parent : did.id).toLowerCase();
        // Store state into class
        this.loader = loader;
        this.model = model;
        this.store = store;
        this.ceramicClient = ceramic;
    }
    async createPassport() {
        this.logger.info(`create new passport for did ${this.did}`);
        const date = new Date();
        const newPassport = {
            issuanceDate: date.toISOString(),
            expiryDate: date.toISOString(),
            stamps: [],
        };
        const stream = await this.store.set("Passport", Object.assign({}, newPassport));
        return stream.toUrl();
    }
    async getPassport() {
        var _a;
        try {
            const passport = await this.store.get("Passport");
            const streamIDs = passport === null || passport === void 0 ? void 0 : passport.stamps.map((ceramicStamp) => {
                return ceramicStamp.credential;
            });
            this.logger.info(`loaded passport for did ${this.did} => ${JSON.stringify(passport)}`);
            if (!passport)
                return false;
            // `stamps` is stored as ceramic URLs - must load actual VC data from URL
            const stampsToLoad = (_a = passport === null || passport === void 0 ? void 0 : passport.stamps.map(async (_stamp) => {
                const { provider, credential } = _stamp;
                try {
                    const loadedCred = await this.loader.load(credential);
                    return {
                        provider,
                        credential: loadedCred.content,
                        streamId: credential,
                    };
                }
                catch (e) {
                    this.logger.error(`Error when loading stamp with streamId ${credential} for did  ${this.did}:  ${JSON.stringify(e)}`);
                    return null;
                }
            })) !== null && _a !== void 0 ? _a : [];
            const loadedStamps = await Promise.all(stampsToLoad);
            const parsePassport = {
                issuanceDate: new Date(passport.issuanceDate),
                expiryDate: new Date(passport.expiryDate),
                stamps: loadedStamps,
            };
            // try pinning passport
            try {
                const passportDoc = await this.store.getRecordDocument(this.model.getDefinitionID("Passport"));
                await this.ceramicClient.pin.add(passportDoc.id);
            }
            catch (e) {
                this.logger.error(`Error when pinning passport for did  ${this.did}: ${JSON.stringify(e)}`);
            }
            return parsePassport;
        }
        catch (e) {
            this.logger.error(`Error when loading passport for did  ${this.did}: ${JSON.stringify(e)}`);
            return undefined;
        }
    }
    async addStamp(stamp) {
        // get passport document from user did data store in ceramic
        const passport = await this.store.get("Passport");
        // ensure the users did matches the credentials subject id otherwise skip the save
        if (passport && this.did === stamp.credential.credentialSubject.id.toLowerCase()) {
            // create a tile for verifiable credential issued from iam server
            const newStampTile = await this.model.createTile("VerifiableCredential", stamp.credential);
            // add stamp provider and streamId to passport stamps array
            const newStamps = passport === null || passport === void 0 ? void 0 : passport.stamps.concat({ provider: stamp.provider, credential: newStampTile.id.toUrl() });
            // merge new stamps array to update stamps on the passport
            const streamId = await this.store.merge("Passport", { stamps: newStamps });
            // try pinning passport
            try {
                await this.ceramicClient.pin.add(streamId);
            }
            catch (e) {
                this.logger.error(`Error when pinning passport for did  ${this.did}:  ${JSON.stringify(e)}`);
            }
        }
    }
    async deleteStamp(streamId) {
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
                const stampStreamId = StreamID.fromString(streamId);
                try {
                    await this.ceramicClient.pin.rm(stampStreamId);
                }
                catch (e) {
                    this.logger.error(`Error when unpinning stamp with id ${stampStreamId.toString()} for did  ${this.did}: ${JSON.stringify(e)}`);
                }
                // try pinning passport
                try {
                    await this.ceramicClient.pin.add(passportStreamId);
                }
                catch (e) {
                    this.logger.error(`Error when pinning passport for did  ${this.did}:  ${JSON.stringify(e)}`);
                }
            }
            else {
                this.logger.info(`unable to find stamp with stream id ${streamId} in passport`);
            }
        }
    }
    async deletePassport() {
        this.logger.info(`deleting passport for did ${this.did}`);
        // Created for development purposes
        await this.store.remove("Passport");
    }
}
//# sourceMappingURL=passportWriter.js.map