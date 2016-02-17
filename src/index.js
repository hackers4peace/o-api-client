import JsonldSerializer from 'rdf-serializer-jsonld'
import JsonldParser from 'rdf-parser-jsonld'
import jld from 'jsonld'
import jldsig from 'jsonld-signatures'

jldsig.use('jsonld', jld)

const jsonld = jld.promises
const jsig = jldsig.promises

const parsers = {
  jsonld: new JsonldParser()
}

const serializers = {
  jsonld: new JsonldSerializer()
}


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
  sign (graph) {
    return serializers.jsonld.serialize(graph)
      .then((json) => {
        return jsig.sign(json[0], {
          privateKeyPem: this.privateKeyPem,
          creator: this.publicKeyUri,
          algorithm: 'LinkedDataSignature2015'
        })
      }).then((signedJson) => {
        return parsers.jsonld.parse(signedJson)
      })
  }

  /**
   * @param doc
   * @returns {Object}
   */
  verify (graph) {
    let doc, publicKey, publicKeyOwner
    return serializers.jsonld.serialize(graph)
      .then((json) => {
        return jsonld.expand(json)
      }).then((expanded) => {
        let signature = expanded.find((entity) => { return entity['https://w3id.org/security#signatureValue'] })
        doc = expanded.find((entity) => { return !entity['https://w3id.org/security#signatureValue'] })
        delete signature['@id']
        doc['https://w3id.org/security#signature'] = [ signature ]
        let keyUri = signature['http://purl.org/dc/terms/creator'][0]['@id']
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
