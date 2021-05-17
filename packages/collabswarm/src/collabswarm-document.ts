import pipe from "it-pipe";
import Libp2p from "libp2p";
import { MessageHandlerFn } from "ipfs-core-types/src/pubsub";
import { Collabswarm } from "./collabswarm";
import { readUint8Iterable, shuffleArray } from "./utils";
import { CRDTProvider } from "./collabswarm-provider";
import { CRDTSyncMessage } from "./collabswarm-message";


export type CollabswarmDocumentChangeHandler<DocType> = (current: DocType, hashes: string[]) => void;

export class CollabswarmDocument<DocType, ChangesType, ChangeFnType, MessageType extends CRDTSyncMessage<ChangesType>> {
  // Only store/cache the full automerge document.
  private _document: DocType = this._provider.newDocument();
  get document(): DocType {
    return this._document;
  }

  private _hashes = new Set<string>();

  private _pubsubHandler: MessageHandlerFn | undefined;

  private _remoteHandlers: { [id: string]: CollabswarmDocumentChangeHandler<DocType> } = {};
  private _localHandlers: { [id: string]: CollabswarmDocumentChangeHandler<DocType> } = {};

  public get libp2p(): Libp2p {
    return (this.swarm.ipfsNode as any).libp2p;
  }

  constructor(
    public readonly swarm: Collabswarm<DocType, ChangesType, ChangeFnType, MessageType>,
    public readonly documentPath: string,
    private readonly _provider: CRDTProvider<DocType, ChangesType, ChangeFnType, MessageType>,
  ) { }

  // https://gist.github.com/alanshaw/591dc7dd54e4f99338a347ef568d6ee9#duplex-it
  public async load(): Promise<boolean> {
    // Pick a peer.
    // TODO: In the future, try to re-use connections that already are open.
    const peers = await this.swarm.ipfsNode.swarm.peers();
    if (peers.length === 0) {
      return false;
    }

    // Shuffle peer array.
    const shuffledPeers = [...peers];
    shuffleArray(shuffledPeers);

    const stream = await (async () => {
      for (const peer of shuffledPeers) {
        try {
          console.log('Selected peer addresses:', peer.addr.toString());
          const docLoadConnection = await this.libp2p.dialProtocol(peer.addr.toString(), ['/collabswarm-automerge/doc-load/1.0.0']);
          return docLoadConnection.stream;
        } catch (err) {
          console.warn('Failed to load document from:', peer.addr.toString(), err);
        }
      }
    })();

    // TODO: Close connection upon receipt of data.
    if (stream) {
      console.log('Opening stream for /collabswarm-automerge/doc-load/1.0.0', stream);
      await pipe(
        stream,
        async source => {
          const assembled = await readUint8Iterable(source);
          const message = this._provider.deserializeMessage(assembled);
          console.log('received /collabswarm-automerge/doc-load/1.0.0 response:', assembled, message);

          if (message.documentId === this.documentPath) {
            await this.sync(message);
          }

          // Return an ACK.
          return [];
        }
      );
      return true;
    } else {
      console.log('Failed to open document on any nodes.', this);
      return false;
    }
  }

  public async pin() {
    // Apply local change w/ automerge.
    const changes = this._provider.getHistory(this.document);

    // Store changes in ipfs.
    const newFileResult = await this.swarm.ipfsNode.add(this._provider.serializeChanges(changes));
    const hash = newFileResult.cid.toString();
    this._hashes.add(hash);

    // Send new message.
    const updateMessage = this._provider.newMessage(this.documentPath);
    for (const oldHash of this._hashes) {
      updateMessage.changes[oldHash] = null;
    }
    updateMessage.changes[hash] = changes;

    if (!this.swarm.config) {
      throw 'Can not pin a file when the node has not been initialized'!;
    }
    this.swarm.ipfsNode.pubsub.publish(this.swarm.config.pubsubDocumentPublishPath, this._provider.serializeMessage(updateMessage));
  }

  public async open(): Promise<boolean> {
    // Open pubsub connection.
    this._pubsubHandler = rawMessage => {
      const message = this._provider.deserializeMessage(rawMessage.data);
      this.sync(message);
    }
    await this.swarm.ipfsNode.pubsub.subscribe(this.documentPath, this._pubsubHandler);

    // Make the messages on this specific to a document.
    this.libp2p.handle('/collabswarm-automerge/doc-load/1.0.0', ({ stream }) => {
      console.log('received /collabswarm-automerge/doc-load/1.0.0 dial');
      const loadMessage = this._provider.newMessage(this.documentPath);
      for (const hash of this._hashes) {
        loadMessage.changes[hash] = null;
      }

      const assembled = this._provider.serializeMessage(loadMessage);
      console.log('sending /collabswarm-automerge/doc-load/1.0.0 response:', assembled, loadMessage);

      // Immediately send the connecting peer either the automerge.save'd document or a list of
      // hashes with the changes that are cached locally.
      pipe(
        [this._provider.serializeMessage(loadMessage)],
        stream,
        async (source: any) =>  {
          // Ignores responses.
          for await (const _ of source) { }
        }
      );
    });

    // Load initial document from peers.
    return await this.load();
  }

  public async close() {
    if (this._pubsubHandler) {
      await this.swarm.ipfsNode.pubsub.unsubscribe(this.documentPath, this._pubsubHandler);
    }
  }

  public async getFile(hash: string): Promise<ChangesType> {
    const assembled = await readUint8Iterable(this.swarm.ipfsNode.files.read(`/ipfs/${hash}`));
    const decoder = new TextDecoder();

    return this._provider.deserializeChanges(decoder.decode(assembled));
  }

  private _fireRemoteUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._remoteHandlers)) {
      handler(this.document, hashes);
    }
  }
  private _fireLocalUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._localHandlers)) {
      handler(this.document, hashes);
    }
  }

  // Given a list of hashes, fetch missing update messages.
  public async sync(message: MessageType) {
    // Only process hashes that we haven't seen yet.
    const newChangeEntries = Object.entries(message.changes).filter(([sentHash]) => sentHash && !this._hashes.has(sentHash));

    // First apply changes that were sent directly.
    let newDocument = this.document;
    const newDocumentHashes: string[] = [];
    const missingDocumentHashes: string[] = [];
    for (const [sentHash, sentChanges] of newChangeEntries) {
      if (sentChanges) {
        // Apply the changes that were sent directly.
        newDocument = this._provider.remoteChange(newDocument, sentChanges);
        newDocumentHashes.push(sentHash);
      } else {
        missingDocumentHashes.push(sentHash);
      }
    }
    if (newDocumentHashes.length) {
      this._document = newDocument;
      for (const newHash of newDocumentHashes) {
        this._hashes.add(newHash);
      }
      this._fireRemoteUpdateHandlers(newDocumentHashes);
    }

    // Then apply missing hashes by fetching them via IPFS.
    for (const missingHash of missingDocumentHashes) {
      // Fetch missing hashes using IPFS.
      this.getFile(missingHash)
        .then(missingChanges => {
          if (missingChanges) {
            this._document = this._provider.remoteChange(this._document, missingChanges);
            this._hashes.add(missingHash);
            this._fireRemoteUpdateHandlers([missingHash]);
          } else {
            console.error(`'/ipfs/${missingHash}' returned nothing`, missingChanges);
          }
        })
        .catch(err => {
          console.error('Failed to fetch missing change from ipfs:', missingHash, err);
        });
    }
  }

  public subscribe(id: string, handler: CollabswarmDocumentChangeHandler<DocType>, originFilter: 'all' | 'remote' | 'local' = 'all') {
    switch (originFilter) {
      case 'all': {
        this._remoteHandlers[id] = handler;
        this._localHandlers[id] = handler;
        break;
      }
      case 'remote': {
        this._remoteHandlers[id] = handler;
        break;
      }
      case 'local': {
        this._localHandlers[id] = handler;
        break;
      }
    }
  }

  public unsubscribe(id: string) {
    if (this._remoteHandlers[id]) {
      delete this._remoteHandlers[id];
    }
    if (this._localHandlers[id]) {
      delete this._localHandlers[id];
    }
  }

  public async change(changeFn: ChangeFnType, message?: string) {
    const [newDocument, changes] = this._provider.localChange(this.document, message || "", changeFn);
    // Apply local change w/ automerge.
    this._document = newDocument;

    // Store changes in ipfs.
    const newFileResult = await this.swarm.ipfsNode.add(this._provider.serializeChanges(changes));
    const hash = newFileResult.cid.toString();
    this._hashes.add(hash);

    // Send new message.
    const updateMessage = this._provider.newMessage(this.documentPath);
    for (const oldHash of this._hashes) {
      updateMessage.changes[oldHash] = null;
    }
    updateMessage.changes[hash] = changes;
    await this.swarm.ipfsNode.pubsub.publish(this.documentPath, this._provider.serializeMessage(updateMessage));

    // Fire change handlers.
    this._fireLocalUpdateHandlers([hash]);
  }
}