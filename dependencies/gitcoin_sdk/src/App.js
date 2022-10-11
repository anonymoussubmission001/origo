// @ts-ignore
import React, { useState } from "react"; // react,

import {extendContextLoader} from '@sphereon/rn-jsonld-signatures';
import {contexts, contextConstants} from '@sphereon/rn-w3c-credentials-context';
import vc from '@sphereon/rn-vc-js';

// import ReactDOM from 'react-dom';
import Modal from 'react-modal';

// Required to set up a suite instance with private key
import {Ed25519VerificationKey2018} from
  '@digitalbazaar/ed25519-verification-key-2018';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';

// @ts-ignore
import logo from "./GitcoinLogo.svg";
import "./App.css";
// import ImportScript from './hooks/importScript';

// --- sdk import
import { PassportReader } from "@gitcoinco/passport-sdk-reader";
import PassportWriter from "@gitcoinco/passport-sdk-writer/dist/writer.js";

import { Provider } from '@self.id/framework'
import { EthereumAuthProvider, useViewerConnection } from '@self.id/framework'

function App({children}) {
  const [addressInput, setAddressInput] = useState("");
  const [streamIdInput, setStreamIdInput] = useState("");
  const [selectedPolicyName, setSelectedPolicyName] = useState("");
  const [passport, setPassport] = useState({});
  const [connection, connect, disconnect] = useViewerConnection();

  // ImportScript("./passport-sdk-writer/dist/writer.js");

  const [modalIsOpen1, setIsOpen1] = React.useState(false);
  const [modalIsOpen2, setIsOpen2] = React.useState(false);

  function openModal1() {
    setIsOpen1(true);
  }
  function closeModal1() {
    setIsOpen1(false);
  }
  function openModal2() {
    setIsOpen2(true);
  }
  function closeModal2() {
    setIsOpen2(false);
  }

  const customStyles = {
    content: {
      top: '50%',
      left: '50%',
      right: 'auto',
      bottom: 'auto',
      marginRight: '-50%',
      transform: 'translate(-50%, -50%)',
    },
  };

  const policy_paypal1 = {
    "apis": [
      {
        "url": "https://api-m.sandbox.paypal.com/v2/checkout/orders/",
        "content-type": "application/json",
        "pattern": "\"currency_code\":\"USD\",\"value\":\"[0-9]+.[0-9]+\",",
        "creds": true
      }
    ],
    "constraints": [
      {
        "value": "098.00",
        "constraint": "GT"
      }
    ],
    "proxies": [
      {
        "host": "localhost",
        "port": "8082",
        "mode": "signature",
        "pubKey": "3282734573475",
        "algorithm": "Ed25519"
      }
    ]
  }

  const policy_paypal2 = {
    "apis": [
      {
        "url": "https://api-m.sandbox.paypal.com/v2/checkout/orders/",
        "content-type": "application/json",
        "pattern": "\"currency_code\":\"USD\",\"value\":\"[0-9]+.[0-9]+\",",
        "creds": true
      }
    ],
    "constraints": [
      {
        "value": "118.00",
        "constraint": "LT"
      }
    ],
    "proxies": [
      {
        "host": "localhost",
        "port": "8082",
        "mode": "signature",
        "pubKey": "3282734573475",
        "algorithm": "Ed25519"
      }
    ]
  }

  // const CREDENTIALS_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1';
  // const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1';
  // const VERES_ONE_CONTEXT_URL = 'https://w3id.org/veres-one/v1';
  // const didContexts = [
  //   DID_CONTEXT_URL,
  //   VERES_ONE_CONTEXT_URL
  // ];
  const {defaultDocumentLoader} = vc;

  const documentLoader = extendContextLoader(async url => {
    const context = contexts[url];
    if(url === 'did:test:context:foo') {
      return {
        contextUrl: null,
        documentUrl: url,
        document: context
      };
    }
    return defaultDocumentLoader(url);
  });

  // passport reader
  const reader = new PassportReader();

  const handleSubmit2 = (event) => {
    event.preventDefault();

    reader.getPassportStream(addressInput).then((result) => {
      setPassport(result);
    });
  };

  async function handleSubmit1(event) {
    event.preventDefault();

    let pw = new PassportWriter(connection.selfID.did);
    await pw.deleteStamp(streamIdInput);
    console.log("stream successfully deleted");
    // check existing stamps here: https://tiles.ceramic.community/
  };

  async function createPassportWriter() {
    // event.preventDefault();
    let pw = new PassportWriter(connection.selfID.did);
    let streamID = await pw.createPassport();
    console.log(streamID);
  }

  async function getPassportWriter() {
    // event.preventDefault();
    let pw = new PassportWriter(connection.selfID.did);
    const ceramicPassport = await pw.getPassport();
    console.log(ceramicPassport);
  }

  async function addStamp(event) {
    event.preventDefault();

    // generate key pair
    // const keyPair = await Ed25519VerificationKey2018.generate();
    // keyPair.id = 'https://example.edu/issuers/keys/1';
    // keyPair.controller = 'https://example.com/i/carol';

    // const suite = new Ed25519Signature2018({
    //   verificationMethod: keyPair.id,
    //   key: keyPair
    // });
    let policy_selected = null;
    console.log("selectedPolicyName:", selectedPolicyName)
    if (selectedPolicyName == "policy_paypal1" || selectedPolicyName == "policy_paypal2") {
	    if (selectedPolicyName == "policy_paypal1") {
		policy_selected = policy_paypal1;
	    } else {
		policy_selected = policy_paypal2;
	    }
    } else {
      console.log("please enter right policy name")
      return
    }

    const requestOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policyname: selectedPolicyName })
    };
    const response = await fetch('/origo', requestOptions)
    console.log(response)
    // if (response != null) {
    let data = await response.json()
    console.log("data", data)
    // }

    // let pw = new PassportWriter(connection.selfID.did);
    let json = JSON.parse(JSON.stringify(connection.selfID.did))
    // console.log("json:", json)
    // let credential = same as the one below

    // const verifiableCredential = [credential] 
    // const id = 'ebc6f1c2';
    // const holder = 'did:ex:12345';

    // const presentation = vc.createPresentation({
    //   verifiableCredential, id, holder
    // });
    // console.log("presentation:", JSON.stringify(presentation, null, 2));

    // let challenge = "12ec21";
    // let options = {presentation, suite, challenge, documentLoader};
    // options.expansionMap = false;
    // const vp = await vc.signPresentation(options);

    // console.log("printing signed presentation:", JSON.stringify(vp, null, 2));

    // const signedVC = await vc.issue({credential, suite, documentLoader});
    // console.log("printing signedVC:", JSON.stringify(signedVC, null, 2));

    // or
    // const result = await vc.verifyCredential({credential: signedVC, suite, documentLoader});
    // console.log("result", result)

    // "issuanceDate": new Date().toISOString(),
    // "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..AUQ3AJ23WM5vMOWNtYKuqZBekRAOUibOMH9XuvOd39my1sO-X9R4QyAXLD2ospssLvIuwmQVhJa-F0xMOnkvBg",
    const newStamp = {
      provider: "ORIGO",
      title: "origo paypal stamp",
      credential: {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "issuer": json["_id"],
        "issuanceDate": data.issuedate,
        "credentialSubject": {
          "id": json["_parentId"],
          "origo_policy": policy_selected
        },
        "type": [
          "VerifiableCredential",
        ],
        "proof": {
          "type": "Ed25519Signature2018",
          "created": new Date().toISOString(),
          "jws": data.signature,
          "proofPurpose": "assertionMethod",
          "verificationMethod": "https://example.edu/issuers/keys/1"
        },
        "expirationDate": data.expiredate
      }
    };
    const pw = new PassportWriter(connection.selfID.did);
    await pw.addStamp(newStamp);
    console.log("adding stamp successfull");
  }

  async function handleConnect(event) {
    event.preventDefault();

    const accounts = await window.ethereum.request({
      method: 'eth_requestAccounts',
    })
    await connect(new EthereumAuthProvider(window.ethereum, accounts[0]))

    // const passportWriter = new PassportWriter(connection.selfID.did);

  };

  return (
    <Provider client={{ceramic: 'testnet-clay'}} session={true}>{children}
      <div className="App">
        <header className="App-header">
          <img src={logo} className="App-logo" alt="logo" />
          <h1>ORIGO Gitcoin Passport Integration</h1>
            {connection.status === 'connected' ? ( 
            <div>
              {connection.selfID.id}
            </div>
            ) : (
            <div>
              Connection ID Placeholder
            </div>
            )
            }
            {connection.status === 'connected' ? (
              <button
                onClick={() => {
                  disconnect()
                }}>
               Disconnect Wallet
              </button>
            ) : 'ethereum' in window ? (
              <button
                disabled={connection.status === 'connecting'}
                onClick={handleConnect}
                >
                Connect Wallet
              </button>
            ) : (
              <p>
                An injected Ethereum provider such as{' '}
                <a href="https://metamask.io/">MetaMask</a> is needed to authenticate.
              </p>
            )}
          <div>Create PassportWriter</div>
          <button
            onClick={() => {
              createPassportWriter()
            }}>
              Create PPWriter
            </button>
          <div>Get PassportWriter</div>
          <button
            onClick={() => {
              getPassportWriter()
            }}>
              Get PPWriter
            </button>
          <div>Select Policy and Add ORIGO Stamp to Ceramic Gitcoin Passport</div>

            <div>
              <button onClick={openModal1}>ORIGO Paypal Policy Greater Than</button>
              <Modal
                isOpen={modalIsOpen1}
                onRequestClose={closeModal1}
                style={customStyles}
                contentLabel="Example Modal1"
              >
                <h2>policy_paypal1</h2>
                <div>
                  {JSON.stringify(policy_paypal1, null, 4)}
                </div>
                <br></br>
                <div>
                  <button onClick={closeModal1}>close</button>
                </div>
              </Modal>
              <button onClick={openModal2}>ORIGO Paypal Policy Less Than</button>
              <Modal
                isOpen={modalIsOpen2}
                onRequestClose={closeModal2}
                style={customStyles}
                contentLabel="Example Modal2"
              >
                <h2>policy_paypal2</h2>
                <div>{JSON.stringify(policy_paypal2, null, 4)}</div>
                <br></br>
                <div>
                  <button onClick={closeModal2}>close</button>
                </div>
              </Modal>
            </div>

          <form>
            <input
              type="text"
              name="inputPolicyName"
              style={{ padding: 12 }}
              // @ts-ignore
              onChange={(e) => setSelectedPolicyName(e.target.value)}
              value={selectedPolicyName}
            />
            <button style={{ padding: 12 }} onClick={addStamp}>
              Enter
            </button>
          </form>
          <div>Enter StreamID to Delete</div>
          <form>
            <input
              type="text"
              name="inputStreamId"
              style={{ padding: 12 }}
              // @ts-ignore
              onChange={(e) => setStreamIdInput(e.target.value)}
              value={streamIdInput}
            />
            <button style={{ padding: 12 }} onClick={handleSubmit1}>
              Enter
            </button>
          </form>
          <div>Enter Wallet Address to Read Passport Data</div>
          <form>
            <input
              type="text"
              name="inputAddress"
              style={{ padding: 12 }}
              // @ts-ignore
              onChange={(e) => setAddressInput(e.target.value)}
              value={addressInput}
            />
            <button style={{ padding: 12 }} onClick={handleSubmit2}>
              Enter
            </button>
          </form>
          {passport && (
            <div style={{ padding: 10, marginTop: 10, fontSize: 14, textAlign: "left" }}>
              <h1 style={{ textAlign: "center" }}>Passport Data</h1>
              {
                // @ts-ignore
                passport?.expiryDate && (
                  <p>
                    Expiry Date:{" "}
                    {
                      // @ts-ignore
                      passport?.expiryDate
                    }
                  </p>
                )
              }
              {
                // @ts-ignore
                passport?.issuanceDate && (
                  <p>
                    Issuance Date:{" "}
                    {
                      // @ts-ignore
                      passport?.issuanceDate
                    }
                  </p>
                )
              }

              {
                // @ts-ignore
                passport?.stamps?.length > 0 && (
                  <div>
                    Stamps:{" "}
                    <ul>
                      {
                        // @ts-ignore
                        passport?.stamps?.map((item, index) => {
                          return <li key={index}>{item.provider}</li>;
                        })
                      }
                    </ul>
                  </div>
                )
              }
            </div>
          )}
        </header>
      </div>
    </Provider>
  );
}

export default App;
