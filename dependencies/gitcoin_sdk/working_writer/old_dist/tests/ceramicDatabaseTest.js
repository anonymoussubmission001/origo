import { DID } from "dids";
import { Ed25519Provider } from "key-did-provider-ed25519";
import { getResolver } from "key-did-resolver";
import testnetAliases from "./integration-test-model-aliases.json";
import { PassportWriter, CERAMIC_CLIENT_TESTNET_URL } from "../src";
let testDID;
let passportWriter;
beforeAll(async () => {
    const TEST_SEED = Uint8Array.from({ length: 32 }, () => Math.floor(Math.random() * 256));
    // Create and authenticate the DID
    testDID = new DID({
        provider: new Ed25519Provider(TEST_SEED),
        resolver: getResolver(),
    });
    await testDID.authenticate();
    passportWriter = new PassportWriter(testDID, CERAMIC_CLIENT_TESTNET_URL, testnetAliases);
});
afterAll(async () => {
    await passportWriter.store.remove("Passport");
});
describe("when there is no passport for the given did", () => {
    beforeEach(async () => {
        await passportWriter.store.remove("Passport");
    });
    it("createPassport creates a passport in ceramic", async () => {
        const actualPassportStreamID = await passportWriter.createPassport();
        expect(actualPassportStreamID).toBeDefined();
        const storedPassport = (await passportWriter.loader.load(actualPassportStreamID)).content;
        const formattedDate = new Date(storedPassport["issuanceDate"]);
        const todaysDate = new Date();
        expect(formattedDate.getDay()).toEqual(todaysDate.getDay());
        expect(formattedDate.getMonth()).toEqual(todaysDate.getMonth());
        expect(formattedDate.getFullYear()).toEqual(todaysDate.getFullYear());
        expect(storedPassport["stamps"]).toEqual([]);
    });
    it("getPassport returns false", async () => {
        const actualPassport = await passportWriter.getPassport();
        expect(actualPassport).toEqual(false);
    });
});
describe("when there is an existing passport without stamps for the given did", () => {
    const existingPassport = {
        issuanceDate: new Date("2022-01-01"),
        expiryDate: new Date("2022-01-02"),
        stamps: [],
    };
    let existingPassportStreamID;
    beforeEach(async () => {
        // ceramicPassport follows the schema definition that ceramic expects
        const ceramicPassport = {
            issuanceDate: existingPassport.issuanceDate,
            expiryDate: existingPassport.expiryDate,
            stamps: existingPassport.stamps,
        };
        const stream = await passportWriter.store.set("Passport", ceramicPassport);
        existingPassportStreamID = stream.toUrl();
    });
    afterEach(async () => {
        await passportWriter.store.remove("Passport");
    });
    it("getPassport retrieves the passport from ceramic", async () => {
        const actualPassport = (await passportWriter.getPassport());
        expect(actualPassport).toBeDefined();
        expect(actualPassport).toEqual(existingPassport);
        expect(actualPassport.stamps).toEqual([]);
    });
    it("addStamp adds a stamp to passport", async () => {
        const credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential"],
            credentialSubject: {
                id: `${passportWriter.did}`,
                "@context": [
                    {
                        hash: "https://schema.org/Text",
                        provider: "https://schema.org/Text",
                    },
                ],
                hash: "randomValuesHash",
                provider: "randomValuesProvider",
            },
            issuer: "did:key:randomValuesIssuer",
            issuanceDate: "2022-04-15T21:04:01.708Z",
            proof: {
                type: "Ed25519Signature2018",
                proofPurpose: "assertionMethod",
                verificationMethod: "did:key:randomValues",
                created: "2022-04-15T21:04:01.708Z",
                jws: "randomValues",
            },
            expirationDate: "2022-05-15T21:04:01.708Z",
        };
        const googleStampFixture = {
            provider: "Google",
            credential,
        };
        await passportWriter.addStamp(googleStampFixture);
        const passport = await passportWriter.store.get("Passport");
        const retrievedStamp = passport === null || passport === void 0 ? void 0 : passport.stamps[0];
        // retrieve streamId stored in credential to load verifiable credential
        const loadedCred = await passportWriter.loader.load(retrievedStamp.credential);
        expect(passport.stamps.length).toEqual(1);
        expect(loadedCred.content).toEqual(credential);
        expect(retrievedStamp.provider).toEqual(googleStampFixture.provider);
    });
});
describe("when there is an existing passport with stamps for the given did", () => {
    const existingPassport = {
        issuanceDate: new Date("2022-01-01"),
        expiryDate: new Date("2022-01-02"),
        stamps: [],
    };
    // these need to be initialized in beforeEach since `credential` needs `passportwriter` to be defined
    let credential;
    let ensStampFixture;
    let googleStampFixture;
    let existingPassportStreamID;
    beforeEach(async () => {
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential"],
            credentialSubject: {
                id: `${passportWriter.did}`,
                "@context": [
                    {
                        hash: "https://schema.org/Text",
                        provider: "https://schema.org/Text",
                    },
                ],
                hash: "randomValuesHash",
                provider: "randomValuesProvider",
            },
            issuer: "did:key:randomValuesIssuer",
            issuanceDate: "2022-04-15T21:04:01.708Z",
            proof: {
                type: "Ed25519Signature2018",
                proofPurpose: "assertionMethod",
                verificationMethod: "did:key:randomValues",
                created: "2022-04-15T21:04:01.708Z",
                jws: "randomValues",
            },
            expirationDate: "2022-05-15T21:04:01.708Z",
        };
        // create a tile for verifiable credential issued from iam server
        const ensStampTile = await passportWriter.model.createTile("VerifiableCredential", credential);
        ensStampFixture = {
            provider: "Ens",
            credential,
            streamId: ensStampTile.id.toUrl(),
        };
        googleStampFixture = {
            provider: "Google",
            credential,
        };
        // add ENS stamp provider and streamId to passport stamps array
        const existingPassportWithStamps = {
            issuanceDate: new Date("2022-01-01"),
            expiryDate: new Date("2022-01-02"),
            stamps: [
                {
                    provider: ensStampFixture.provider,
                    credential: ensStampTile.id.toUrl(),
                },
            ],
        };
        const stream = await passportWriter.store.set("Passport", existingPassportWithStamps);
        existingPassportStreamID = stream.toUrl();
    });
    afterEach(async () => {
        await passportWriter.store.remove("Passport");
    });
    it("getPassport retrieves the passport and stamps from ceramic", async () => {
        const actualPassport = (await passportWriter.getPassport());
        const formattedDate = new Date(actualPassport["issuanceDate"]);
        expect(actualPassport).toBeDefined();
        expect(formattedDate.getDay()).toEqual(existingPassport.issuanceDate.getDay());
        expect(formattedDate.getMonth()).toEqual(existingPassport.issuanceDate.getMonth());
        expect(formattedDate.getFullYear()).toEqual(existingPassport.issuanceDate.getFullYear());
        expect(actualPassport.stamps[0]).toEqual(ensStampFixture);
    });
    it("addStamp adds a stamp to passport", async () => {
        await passportWriter.addStamp(googleStampFixture);
        const passport = await passportWriter.store.get("Passport");
        const retrievedStamp = passport === null || passport === void 0 ? void 0 : passport.stamps[1];
        // retrieve streamId stored in credential to load verifiable credential
        const loadedCred = await passportWriter.loader.load(retrievedStamp.credential);
        expect(passport.stamps.length).toEqual(2);
        expect(loadedCred.content).toEqual(credential);
        expect(retrievedStamp.provider).toEqual(googleStampFixture.provider);
    });
});
describe("when there is an existing passport with stamps for the given did that needs to deleted", () => {
    const existingPassport = {
        issuanceDate: new Date("2022-01-01"),
        expiryDate: new Date("2022-01-02"),
        stamps: [],
    };
    // these need to be initialized in beforeEach since `credential` needs `ceramicDatabase` to be defined
    let credential;
    let ensStampFixture;
    let googleStampFixture;
    let poapStampFixture;
    let existingPassportStreamID;
    let existingEnsStampTileStreamID;
    let existingGoogleStampTileStreamID;
    let existingPoapStampTileStreamID;
    beforeEach(async () => {
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential"],
            credentialSubject: {
                id: `${passportWriter.did}`,
                "@context": [
                    {
                        hash: "https://schema.org/Text",
                        provider: "https://schema.org/Text",
                    },
                ],
                hash: "randomValuesHash",
                provider: "randomValuesProvider",
            },
            issuer: "did:key:randomValuesIssuer",
            issuanceDate: "2022-04-15T21:04:01.708Z",
            proof: {
                type: "Ed25519Signature2018",
                proofPurpose: "assertionMethod",
                verificationMethod: "did:key:randomValues",
                created: "2022-04-15T21:04:01.708Z",
                jws: "randomValues",
            },
            expirationDate: "2022-05-15T21:04:01.708Z",
        };
        ensStampFixture = {
            provider: "Ens",
            credential,
        };
        googleStampFixture = {
            provider: "Google",
            credential,
        };
        poapStampFixture = {
            provider: "POAP",
            credential,
        };
        // create the tiles for verifiable credentials
        const ensStampTile = await passportWriter.model.createTile("VerifiableCredential", credential);
        const googleStampTile = await passportWriter.model.createTile("VerifiableCredential", credential);
        const poapStampTile = await passportWriter.model.createTile("VerifiableCredential", credential);
        existingEnsStampTileStreamID = ensStampTile.id.toUrl();
        existingGoogleStampTileStreamID = googleStampTile.id.toUrl();
        existingPoapStampTileStreamID = poapStampTile.id.toUrl();
        // add ENS stamp provider and streamId to passport stamps array
        const existingPassportWithStamps = {
            issuanceDate: new Date("2022-01-01"),
            expiryDate: new Date("2022-01-02"),
            stamps: [
                {
                    provider: ensStampFixture.provider,
                    credential: ensStampTile.id.toUrl(),
                },
                {
                    provider: googleStampFixture.provider,
                    credential: googleStampTile.id.toUrl(),
                },
                {
                    provider: poapStampFixture.provider,
                    credential: poapStampTile.id.toUrl(),
                },
            ],
        };
        const stream = await passportWriter.store.set("Passport", existingPassportWithStamps);
        existingPassportStreamID = stream.toUrl();
    });
    afterEach(async () => {
        await passportWriter.store.remove("Passport");
    });
    it("deleteStamp deletes an existing stamp from passport", async () => {
        await passportWriter.deleteStamp(existingGoogleStampTileStreamID);
        // The deletion will not be reflected immediatly, we need to wait a bit ...
        await new Promise((r) => setTimeout(r, 2000));
        const passport = await passportWriter.store.get("Passport");
        expect(passport.stamps.length).toEqual(2);
        expect(passport.stamps.findIndex((stamp) => {
            return stamp.credential === existingEnsStampTileStreamID;
        })).toEqual(0);
        expect(passport.stamps.findIndex((stamp) => {
            return stamp.credential === existingPoapStampTileStreamID;
        })).toEqual(1);
        expect(passport.stamps.findIndex((stamp) => {
            return stamp.credential === existingGoogleStampTileStreamID;
        })).toEqual(-1);
    });
});
describe("when loading a stamp from a passport fails", () => {
    const existingPassport = {
        issuanceDate: new Date("2022-01-01"),
        expiryDate: new Date("2022-01-02"),
        stamps: [],
    };
    // these need to be initialized in beforeEach since `credential` needs `passportWriter` to be defined
    let ensCredential;
    let poapCredential;
    let googleCredential;
    let ensStampFixture;
    let googleStampFixture;
    let poapStampFixture;
    let existingPassportStreamID;
    let existingEnsStampTileStreamID;
    let existingPoapStampTileStreamID;
    beforeEach(async () => {
        const createVC = function (provider) {
            return {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential"],
                credentialSubject: {
                    id: `${passportWriter.did}`,
                    "@context": [
                        {
                            hash: "https://schema.org/Text",
                            provider: "https://schema.org/Text",
                        },
                    ],
                    hash: "randomValuesHash",
                    provider: provider,
                },
                issuer: "did:key:randomValuesIssuer",
                issuanceDate: "2022-04-15T21:04:01.708Z",
                proof: {
                    type: "Ed25519Signature2018",
                    proofPurpose: "assertionMethod",
                    verificationMethod: "did:key:randomValues",
                    created: "2022-04-15T21:04:01.708Z",
                    jws: "randomValues",
                },
                expirationDate: "2022-05-15T21:04:01.708Z",
            };
        };
        ensCredential = createVC("Ens");
        poapCredential = createVC("POAP");
        googleCredential = createVC("Google");
        ensStampFixture = {
            provider: "Ens",
            credential: ensCredential,
        };
        googleStampFixture = {
            provider: "Google",
            credential: googleCredential,
        };
        poapStampFixture = {
            provider: "POAP",
            credential: poapCredential,
        };
        // create the tiles for verifiable credentials
        const ensStampTile = await passportWriter.model.createTile("VerifiableCredential", ensCredential);
        const poapStampTile = await passportWriter.model.createTile("VerifiableCredential", googleCredential);
        existingEnsStampTileStreamID = ensStampTile.id.toUrl();
        existingPoapStampTileStreamID = poapStampTile.id.toUrl();
        // add ENS stamp provider and streamId to passport stamps array
        const existingPassportWithStamps = {
            issuanceDate: new Date("2022-01-01"),
            expiryDate: new Date("2022-01-02"),
            stamps: [
                {
                    provider: ensStampFixture.provider,
                    credential: ensStampTile.id.toUrl(),
                },
                {
                    provider: googleStampFixture.provider,
                    credential: "ceramic://SOME_BAD_ID_FOR_CERAMIC",
                },
                {
                    provider: poapStampFixture.provider,
                    credential: poapStampTile.id.toUrl(),
                },
            ],
        };
        const stream = await passportWriter.store.set("Passport", existingPassportWithStamps);
        existingPassportStreamID = stream.toUrl();
    });
    afterEach(async () => {
        await passportWriter.store.remove("Passport");
    });
    it("ignores the failed stamp and returns null for the stamp that failed", async () => {
        // The deletion will not be reflected immediatly, we need to wait a bit ...
        await new Promise((r) => setTimeout(r, 2000));
        const passport = (await passportWriter.getPassport());
        expect(passport.stamps.length).toEqual(3);
        expect(passport.stamps.findIndex((stamp) => {
            return stamp && stamp.credential.credentialSubject.provider === "Ens";
        })).toEqual(0);
        // The Google stamps should not be readable, we expect null on that position
        expect(passport.stamps.findIndex((stamp) => {
            return stamp === null;
        })).toEqual(1);
        expect(passport.stamps.findIndex((stamp) => {
            return stamp && stamp.credential.credentialSubject.provider === "Google";
        })).toEqual(2);
    });
});
//# sourceMappingURL=ceramicDatabaseTest.js.map