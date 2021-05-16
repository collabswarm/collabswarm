import { MessageHandlerFn } from "ipfs-core-types/src/pubsub";
import * as fs from 'fs';
import { CollabswarmConfig, DEFAULT_CONFIG } from "./collabswarm-config";
import { CRDTSyncMessage } from "./collabswarm-message";
import { Collabswarm } from "./collabswarm";
import { CollabswarmDocument } from "./collabswarm-document";
import { CRDTProvider } from "./collabswarm-provider";

export const DEFAULT_NODE_CONFIG: CollabswarmConfig = {
  ipfs: {
    relay: {
      enabled: true, // enable circuit relay dialer and listener
      hop: {
        enabled: true // enable circuit relay HOP (make this node a relay)
      }
    },
    config: {
      Addresses: {
        Swarm: [
          '/ip4/0.0.0.0/tcp/4003/ws',
          '/ip4/0.0.0.0/tcp/4001',
          '/ip6/::/tcp/4002'
        ]
      },
      Bootstrap: [],
    }
  },

  pubsubDocumentPrefix: '/document/',
  pubsubDocumentPublishPath: '/documents'
};

export class CollabswarmNode<DocType, ChangesType, ChangeFnType, MessageType extends CRDTSyncMessage<ChangesType>> {
  private _swarm = new Collabswarm(this.provider);
  public get swarm(): Collabswarm<DocType, ChangesType, ChangeFnType, MessageType> {
    return this._swarm;
  }

  private readonly _subscriptions = new Map<string, CollabswarmDocument<DocType, ChangesType, ChangeFnType, MessageType>>();
  private readonly _seenCids = new Set<string>();

  private _docPublishHandler: MessageHandlerFn | null = null;

  constructor(
    public readonly provider: CRDTProvider<DocType, ChangesType, ChangeFnType, MessageType>,
    public readonly config: CollabswarmConfig = DEFAULT_NODE_CONFIG,
  ) {}

  // Start
  public async start() {
    await this.swarm.initialize(this.config);
    // console.log('Node Addresses:', this.swarm.ipfsInfo.addresses);
    const websocketAddress = this.swarm.ipfsInfo.addresses.find((address: any) => address.toString().includes('/ws/'));
    const clientConfig = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as CollabswarmConfig;
    if (websocketAddress) {
      clientConfig.ipfs.config.Bootstrap.push(websocketAddress);
    }
    // TODO: Make this automatically generated by webrtc-star-signal (and integrate that into this).
    const starSignalAddress = '/ip4/127.0.0.1/tcp/9090/wss/p2p-webrtc-star';
    if (starSignalAddress) {
      clientConfig.ipfs.config.Addresses.Swarm.push(starSignalAddress);
    }
    const clientConfigFile = process.env.REACT_APP_CLIENT_CONFIG_FILE || 'client-config.env';
    fs.writeFile(clientConfigFile, `REACT_APP_CLIENT_CONFIG='${JSON.stringify(clientConfig)}'`, (err: any) => {
      if (err) {
        console.error(`Failed to write ${clientConfigFile}:`, err);
      } else {
        console.log(`Wrote ${clientConfigFile}:`, clientConfig);
      }
    })

    // Open a pubsub channel (set by some config) for controlling this swarm of listeners.
    // TODO: Add a '/document/<id>' prefix to all "normal" document paths.
    this._docPublishHandler = rawMessage => {
      try {
        const thisNodeId = this.swarm.ipfsInfo.id.toString();
        const senderNodeId = rawMessage.from;

        if (thisNodeId !== senderNodeId) {
          const message = this.provider.deserializeMessage(rawMessage.data);
          console.log('Received Document Publish message:', rawMessage);
          const docRef = this.swarm.doc(message.documentId);

          if (docRef) {
            // Also add a subscription that pins new received files.
            this._subscriptions.set(message.documentId, docRef);
            docRef.subscribe('pinning-handler', (doc, hashes) => {
              for (const cid of hashes) {
                if (!this._seenCids.has(cid)) {
                  // TODO: Handle this operation failing (retry).
                  this.swarm.ipfsNode.pin.add(cid);
                  this._seenCids.add(cid);
                }
              }
            });

            // Listen to the file.
            docRef.open();

            // Pin all of the files that were received.
            for (const cid of Object.keys(message.changes)) {
              if (!this._seenCids.has(cid)) {
                // TODO: Handle this operation failing (retry).
                this.swarm.ipfsNode.pin.add(cid);
                this._seenCids.add(cid);
              }
            }
          } else {
            console.warn('Failed to process incoming document pin message:', rawMessage);
            console.warn('Unable to load document', message.documentId);
          }
        } else {
          console.log('Skipping publish message from this node...');
        }
      } catch (err) {
        console.error('Failed to process incoming document pin message:', rawMessage);
        console.error('Error:', err);
      }
    };
    await this.swarm.ipfsNode.pubsub.subscribe(this.config.pubsubDocumentPublishPath, this._docPublishHandler);
    console.log(`Listening for pinning requests on: ${this.config.pubsubDocumentPublishPath}`)
  }

  public stop() {
    if (this._docPublishHandler) {
      this.swarm.ipfsNode.pubsub.unsubscribe(this.config.pubsubDocumentPublishPath, this._docPublishHandler);
    }
    if (this._subscriptions) {
      for (const [id, ref] of this._subscriptions) {
        ref.unsubscribe('pinning-handler');
      }
    }
  }
}
  