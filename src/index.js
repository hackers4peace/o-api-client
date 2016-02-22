import JsonldSerializer from 'rdf-serializer-jsonld'
import JsonldParser from 'rdf-parser-jsonld'

const parsers = {
  jsonld: new JsonldParser()
}

const serializers = {
  jsonld: new JsonldSerializer()
}


class Client {

  /**
   * @param key { privPem: '', uri: '' }
   * @param deps { forge: {}, jsonld: {}, jsigs: {} }
   */
  constructor (key, deps) {
    deps.jsigs.use('jsonld', deps.jsonld)
    this.jsonld = deps.jsonld.promises
    this.jsig = deps.jsigs.promises
    this.fetch = deps.fetch
    this.privateKeyPem = key.privPem
    this.publicKeyUri = key.uri
  }

  /**
   * @param doc
   * @returns {Object}
   */
  sign (graph) {
    return serializers.jsonld.serialize(graph)
      .then((json) => {
        return this.jsig.sign(json[0], {
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
        return this.jsonld.expand(json)
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
        return this.jsonld.compact(key, 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKey = compacted
        return this.fetch(publicKey.owner)
      }).then((res) => {
        return res.json()
      }).then((identity) => {
        return this.jsonld.compact(identity[0], 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKeyOwner = compacted
        publicKeyOwner.publicKey = publicKey
        return this.jsig.verify(doc, {
          publicKey: publicKey,
          publicKeyOwner: publicKeyOwner
        })
      })
  }
}

export { Client as default }
