// "use strict";
/* eslint no-console: ["error", { allow: ["error"] }] */
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.PassportWriter = exports.getPassportModel = exports.CERAMIC_CLIENT_MAINNET_URL = exports.CERAMIC_CLIENT_TESTNET_URL = void 0;
var http_client_1 = require("@ceramicnetwork/http-client");
var datamodel_1 = require("@glazed/datamodel");
var did_datastore_1 = require("@glazed/did-datastore");
var tile_loader_1 = require("@glazed/tile-loader");
var streamid_1 = require("@ceramicnetwork/streamid");
// -- Published Models on mainnet and testnet
var passportModel_testnet_json_1 = require("./passportModel.testnet.json");
var passportModel_mainnet_json_1 = require("./passportModel.mainnet.json");
// Ceramic Testnet URL - must use with testnet passportModel
exports.CERAMIC_CLIENT_TESTNET_URL = "https://ceramic-clay.3boxlabs.com";
// Ceramic Mainnet URL - must use with mainnet passportModel
exports.CERAMIC_CLIENT_MAINNET_URL = "https://ceramic.passport-iam.gitcoin.co";
// get the passportModel to read/write to and feed it into the PassportWriter along
// with the matching host url (PassportWriter defaults to using testnet)
var getPassportModel = function (network) {
    return network === "mainnet" ? passportModel_mainnet_json_1["default"] : passportModel_testnet_json_1["default"];
};
exports.getPassportModel = getPassportModel;
// --- Define an implentation of the DataStorageBase to read/write to Ceramic
var PassportWriter = /** @class */ (function () {
    function PassportWriter(did, ceramicHost, passportModel, logger) {
        if (logger) {
            this.logger = logger;
        }
        else {
            this.logger = console;
        }
        // Create the Ceramic instance and inject the DID
        var ceramic = new http_client_1.CeramicClient(ceramicHost !== null && ceramicHost !== void 0 ? ceramicHost : exports.CERAMIC_CLIENT_TESTNET_URL);
        ceramic.setDID(did)["catch"](function (e) {
            console.error(e);
        });
        // Create the loader, model and store
        var loader = new tile_loader_1.TileLoader({ ceramic: ceramic });
        var model = new datamodel_1.DataModel({ ceramic: ceramic, aliases: passportModel !== null && passportModel !== void 0 ? passportModel : passportModel_testnet_json_1["default"] });
        var store = new did_datastore_1.DIDDataStore({ loader: loader, ceramic: ceramic, model: model });
        // Store the users did:pkh (not the session did)
        this.did = (did.hasParent ? did.parent : did.id).toLowerCase();
        // Store state into class
        this.loader = loader;
        this.model = model;
        this.store = store;
        this.ceramicClient = ceramic;
    }
    PassportWriter.prototype.createPassport = function () {
        return __awaiter(this, void 0, void 0, function () {
            var date, newPassport, stream;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.logger.info("create new passport for did ".concat(this.did));
                        date = new Date();
                        newPassport = {
                            issuanceDate: date.toISOString(),
                            expiryDate: date.toISOString(),
                            stamps: []
                        };
                        return [4 /*yield*/, this.store.set("Passport", __assign({}, newPassport))];
                    case 1:
                        stream = _a.sent();
                        return [2 /*return*/, stream.toUrl()];
                }
            });
        });
    };
    PassportWriter.prototype.getPassport = function () {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var passport, streamIDs, stampsToLoad, loadedStamps, parsePassport, passportDoc, e_1, e_2;
            var _this = this;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _b.trys.push([0, 8, , 9]);
                        return [4 /*yield*/, this.store.get("Passport")];
                    case 1:
                        passport = _b.sent();
                        streamIDs = passport === null || passport === void 0 ? void 0 : passport.stamps.map(function (ceramicStamp) {
                            return ceramicStamp.credential;
                        });
                        this.logger.info("loaded passport for did ".concat(this.did, " => ").concat(JSON.stringify(passport)));
                        if (!passport)
                            return [2 /*return*/, false];
                        stampsToLoad = (_a = passport === null || passport === void 0 ? void 0 : passport.stamps.map(function (_stamp) { return __awaiter(_this, void 0, void 0, function () {
                            var provider, credential, loadedCred, e_3;
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        provider = _stamp.provider, credential = _stamp.credential;
                                        _a.label = 1;
                                    case 1:
                                        _a.trys.push([1, 3, , 4]);
                                        return [4 /*yield*/, this.loader.load(credential)];
                                    case 2:
                                        loadedCred = _a.sent();
                                        return [2 /*return*/, {
                                                provider: provider,
                                                credential: loadedCred.content,
                                                streamId: credential
                                            }];
                                    case 3:
                                        e_3 = _a.sent();
                                        this.logger.error("Error when loading stamp with streamId ".concat(credential, " for did  ").concat(this.did, ":  ").concat(JSON.stringify(e_3)));
                                        return [2 /*return*/, null];
                                    case 4: return [2 /*return*/];
                                }
                            });
                        }); })) !== null && _a !== void 0 ? _a : [];
                        return [4 /*yield*/, Promise.all(stampsToLoad)];
                    case 2:
                        loadedStamps = _b.sent();
                        parsePassport = {
                            issuanceDate: new Date(passport.issuanceDate),
                            expiryDate: new Date(passport.expiryDate),
                            stamps: loadedStamps
                        };
                        _b.label = 3;
                    case 3:
                        _b.trys.push([3, 6, , 7]);
                        return [4 /*yield*/, this.store.getRecordDocument(this.model.getDefinitionID("Passport"))];
                    case 4:
                        passportDoc = _b.sent();
                        return [4 /*yield*/, this.ceramicClient.pin.add(passportDoc.id)];
                    case 5:
                        _b.sent();
                        return [3 /*break*/, 7];
                    case 6:
                        e_1 = _b.sent();
                        this.logger.error("Error when pinning passport for did  ".concat(this.did, ": ").concat(JSON.stringify(e_1)));
                        return [3 /*break*/, 7];
                    case 7: return [2 /*return*/, parsePassport];
                    case 8:
                        e_2 = _b.sent();
                        this.logger.error("Error when loading passport for did  ".concat(this.did, ": ").concat(JSON.stringify(e_2)));
                        return [2 /*return*/, undefined];
                    case 9: return [2 /*return*/];
                }
            });
        });
    };
    PassportWriter.prototype.addStamp = function (stamp) {
        return __awaiter(this, void 0, void 0, function () {
            var passport, newStampTile, newStamps, streamId, e_4;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.store.get("Passport")];
                    case 1:
                        passport = _a.sent();
                        if (!(passport && this.did === stamp.credential.credentialSubject.id.toLowerCase())) return [3 /*break*/, 7];
                        return [4 /*yield*/, this.model.createTile("VerifiableCredential", stamp.credential)];
                    case 2:
                        newStampTile = _a.sent();
                        newStamps = passport === null || passport === void 0 ? void 0 : passport.stamps.concat({ provider: stamp.provider, credential: newStampTile.id.toUrl() });
                        return [4 /*yield*/, this.store.merge("Passport", { stamps: newStamps })];
                    case 3:
                        streamId = _a.sent();
                        _a.label = 4;
                    case 4:
                        _a.trys.push([4, 6, , 7]);
                        return [4 /*yield*/, this.ceramicClient.pin.add(streamId)];
                    case 5:
                        _a.sent();
                        return [3 /*break*/, 7];
                    case 6:
                        e_4 = _a.sent();
                        this.logger.error("Error when pinning passport for did  ".concat(this.did, ":  ").concat(JSON.stringify(e_4)));
                        return [3 /*break*/, 7];
                    case 7: return [2 /*return*/];
                }
            });
        });
    };
    PassportWriter.prototype.deleteStamp = function (streamId) {
        return __awaiter(this, void 0, void 0, function () {
            var passport, itemIndex, passportStreamId, stampStreamId, e_5, e_6;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.store.get("Passport")];
                    case 1:
                        passport = _a.sent();
                        if (!(passport && passport.stamps)) return [3 /*break*/, 11];
                        itemIndex = passport.stamps.findIndex(function (stamp) {
                            return stamp.credential === streamId;
                        });
                        if (!(itemIndex != -1)) return [3 /*break*/, 10];
                        // Remove the stamp from the stamp list
                        passport.stamps.splice(itemIndex, 1);
                        return [4 /*yield*/, this.store.merge("Passport", { stamps: passport.stamps })];
                    case 2:
                        passportStreamId = _a.sent();
                        stampStreamId = streamid_1.StreamID.fromString(streamId);
                        _a.label = 3;
                    case 3:
                        _a.trys.push([3, 5, , 6]);
                        return [4 /*yield*/, this.ceramicClient.pin.rm(stampStreamId)];
                    case 4:
                        _a.sent();
                        return [3 /*break*/, 6];
                    case 5:
                        e_5 = _a.sent();
                        this.logger.error("Error when unpinning stamp with id ".concat(stampStreamId.toString(), " for did  ").concat(this.did, ": ").concat(JSON.stringify(e_5)));
                        return [3 /*break*/, 6];
                    case 6:
                        _a.trys.push([6, 8, , 9]);
                        return [4 /*yield*/, this.ceramicClient.pin.add(passportStreamId)];
                    case 7:
                        _a.sent();
                        return [3 /*break*/, 9];
                    case 8:
                        e_6 = _a.sent();
                        this.logger.error("Error when pinning passport for did  ".concat(this.did, ":  ").concat(JSON.stringify(e_6)));
                        return [3 /*break*/, 9];
                    case 9: return [3 /*break*/, 11];
                    case 10:
                        this.logger.info("unable to find stamp with stream id ".concat(streamId, " in passport"));
                        _a.label = 11;
                    case 11: return [2 /*return*/];
                }
            });
        });
    };
    PassportWriter.prototype.deletePassport = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.logger.info("deleting passport for did ".concat(this.did));
                        // Created for development purposes
                        return [4 /*yield*/, this.store.remove("Passport")];
                    case 1:
                        // Created for development purposes
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    return PassportWriter;
}());
exports.PassportWriter = PassportWriter;
