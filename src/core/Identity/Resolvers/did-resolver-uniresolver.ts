const axios = require('axios').default;

import { DidResolver } from './did-resolver-base';
import { DidDocument } from '../commons';

/**
 * @classdesc Resolver class which is based on the endpoint of https://dev.uniresolver.io/.
 * Can be used resolve Documents for any DID Method supported by the service.
 * @extends {DidResolver}
 */
export class UniversalDidResolver extends DidResolver {
    async resolveDidDocumet(did: string): Promise<DidDocument> {
        let returned = await axios.get('https://dev.uniresolver.io/1.0/identifiers/' + did);
        return returned.data;
    }

    /**
     *
     * @param {string} did - DID to resolve the DID Document for.
     * @returns A promise which resolves to a {DidDocument}
     * @override resolve(did) method of the {DidResolver}
     * @remarks Unlike other resolvers this class can resolve Documents for many DID Methods.
     * Therefore the check in the parent class needs to be overridden.
     */
    resolve(did: string): Promise<DidDocument> {
        return this.resolveDidDocumet(did);
    }
}
