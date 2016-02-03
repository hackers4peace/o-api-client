import jld from 'jsonld'
import jldsig from 'jsonld-signatures'

jldsig.use('jsonld', jld)

const jsonld = jld.promises
const jsig = jldsig.promises

class Client {

  /**
   * @param privateKeyPem
   * @param publicKeyUri
   */
  constructor (privateKeyPem, publicKeyUri) {
    this.privateKeyPem = privateKeyPem
    this.publicKeyUri = publicKeyUri
  }

  /**
   * @param document
   * @returns {Object}
   */
  sign (document) {
    return jsig.sign(document, {
      privateKeyPem: this.privateKeyPem,
      creator: this.publicKeyUri
    })
  }

}

export { Client as default }
