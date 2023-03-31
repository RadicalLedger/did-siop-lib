import { DidResolver } from './did-resolver-base';
import { Resolver } from 'did-resolver';
import { getResolver } from 'ethr-did-resolver';

import { DidDocument } from '../commons';

/**
 * @classdesc Resolver class for Ethereum DIDs
 * @extends {DidResolver}
 */
export class EthrDidResolver extends DidResolver {
    async resolveDidDocumet(did: string): Promise<DidDocument | undefined> {
        const providerConfig = {
            name: 'rinkeby',
            rpcUrl: 'https://rinkeby.infura.io/v3/e0a6ac9a2c4a4722970325c36b728415'
        };
        let ethrDidResolver = getResolver(providerConfig);
        const didResolver = new Resolver(ethrDidResolver);
        try {
            let result: any = await didResolver.resolve(did);
            let didDoc: DidDocument = { ...result.didDocument };
            return didDoc;
        } catch (e) {
            return undefined;
        }
    }
}
