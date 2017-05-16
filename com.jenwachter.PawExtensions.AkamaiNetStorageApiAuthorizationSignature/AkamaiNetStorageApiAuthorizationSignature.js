// https://paw.cloud/docs/dynamic-values/encoding_crypto#HMAC_Signature
function signHmac256(key, input) {
  var dv = DynamicValue('com.luckymarmot.HMACDynamicValue', {
    input: input,
    key: key,
    algorithm: 3,
    uppercase: false,
    encoding: 'Base64'
  });
  return dv.getEvaluatedString();
}

/**
 * Parses a URI
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * https://github.com/get/parseuri
 */
function parseuri(str) {
  var re = /^(?:(?![^:@]+:[^:@\/]*@)(http|https|ws|wss):\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/;
  var parts = ['source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'];

  var src = str,
    b = str.indexOf('['),
    e = str.indexOf(']');

  if (b != -1 && e != -1) {
    str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
  }

  var m = re.exec(str || ''),
    uri = {},
    i = 14;

  while (i--) {
    uri[parts[i]] = m[i] || '';
  }

  if (b != -1 && e != -1) {
    uri.source = src;
    uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
    uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
    uri.ipv6uri = true;
  }

  return uri;
}

var AkamaiNetStorageApiAuthorizationSignature = function () {

  this.evaluate = function (context) {

    var request = context.getCurrentRequest();

    var authData = request.headers['X-Akamai-ACS-Auth-Data'];
    var action = request.headers['X-Akamai-ACS-Action'];
    var urlParts = parseuri(request.url);

    var dataToSign = authData + '' + urlParts.path + '\n' + 'x-akamai-acs-action:' + action + '\n';

    return signHmac256(this.key, dataToSign);

  };

};

/**
 * API Client Authentication docs:
 * https://control.akamai.com/dl/customers/NS/NS_http_api_FS.pdf#page=15
 */
AkamaiNetStorageApiAuthorizationSignature.identifier = 'com.jenwachter.PawExtensions.AkamaiNetStorageApiAuthorizationSignature';
AkamaiNetStorageApiAuthorizationSignature.title = 'Akamai NetStorage Authorization Signature';
AkamaiNetStorageApiAuthorizationSignature.help = 'https://github.com/jenwachter/Paw-AkamaiNetStorageApiAuthorizationSignature';
AkamaiNetStorageApiAuthorizationSignature.inputs = [
    DynamicValueInput('key', 'Key', 'String')
];

registerDynamicValueClass(AkamaiNetStorageApiAuthorizationSignature);
