import jld from 'jsonld'
import jldsig from 'jsonld-signatures'

jldsig.use('jsonld', jld)

const jsonld = jld.promises
const jsig = jldsig.promises

class Client {

  /**
   * @param fetch
   * @param privateKeyPem
   * @param publicKeyUri
   */
  constructor (fetch, privateKeyPem, publicKeyUri) {
    this.fetch = fetch
    this.privateKeyPem = privateKeyPem
    this.publicKeyUri = publicKeyUri
  }

  /**
   * @param doc
   * @returns {Object}
   */
  sign (doc) {
    return jsig.sign(doc, {
      privateKeyPem: this.privateKeyPem,
      creator: this.publicKeyUri,
      algorithm: 'LinkedDataSignature2015'
    })
  }

  /**
   * @param doc
   * @returns {Object}
   */
  verify (doc) {
    let publicKey, publicKeyOwner
    return jsonld.expand(doc)
      .then((expanded) => {
        let keyUri = expanded[0]['https://w3id.org/security#signature'][0]['http://purl.org/dc/terms/creator'][0]['@id']
        return this.fetch(keyUri)
      }).then((res) => {
        return res.json()
      }).then((key) => {
        return jsonld.compact(key, 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKey = compacted
        return this.fetch(publicKey.owner)
      }).then((res) => {
        return res.json()
      }).then((identity) => {
        return jsonld.compact(identity[0], 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKeyOwner = compacted
        publicKeyOwner.publicKey = publicKey
        return jsig.verify(doc, {
          publicKey: publicKey,
          publicKeyOwner: publicKeyOwner
        })
      })
  }
}

export { Client as default }
