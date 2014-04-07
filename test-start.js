var th = require('telehash');

var mySeeds = {
  "63cccdae18e2ef82a21c0ae5b3daeaf74e22d74aec4d8dcb5a91a80731fe3e7f": {
    "paths": [
      {
        "type": "ipv4",
        "ip": "86.52.36.95",
        "port": 42424
      },
      {
        "type": "ipv6",
        "ip": "fe80::c685:8ff:fe92:4bbd",
        "port": 42424
      },
      {
        "type": "http",
        "http": "http://86.52.36.95:42424"
      }
    ],
    "parts": {
      "3a": "b2383fe3bfe7b39c83084cc400a88fc6627238259ae1ed8a8516d3ec8897f2f9",
      "2a": "a172428fc3a8acf16a242adfe253862ef1b68796bb96603d7bbad42d1b329c8b",
      "1a": "a6db31a4ab56d72b6be28e8bb495c35f36cf6e04"
    },
    "keys": {
      "3a": "snezdMcJsW3SQV9OVpUogh52hc8cUbS9NBcL20Q/YH4=",
      "2a": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ArLEqoXnKdN4xrrP0k/bbdVDgKUVA1hH/hzl+7596c9a1raQldQxVFVIsRGwV8V8vUFoOhv2FlGkpdSvJ8zdFCaF3budMqp03UBuhE6wwPa+WZLaqh+a1JvLm4wW3fB9XIaWNnJibkLBrZC8FVObjxOsS7YP/V+y0NI65e0bW38xM+MJO3AWpMorE5lYi2qR9kxy6WSLBFf/egokOL4m/r4TKnWnFrjStwf8BAsOVCsTU+7fRsjC0G0PLbxU6MVJ4XRYwJoFdKHwKbbBMx8poRDrNWleibBc1QZc/TglDSENFe7qqDzaaUcW7Yb7j9/Ie+r8lL0FTkzTxykYWt22wIDAQAB",
      "1a": "KsNJrT3BJbF3r0Lh0Nn8O3H6TNIFQCLAawqrV++yZXUiT/4TDAzzsA=="
    },
    "bridge": true
  }
}


th.init({seeds:mySeeds}, function(err, self){
	if(err) return console.log('hashname generation/startup failed',err);
	console.log(self.id);
	
	self.start("5581ca9928b9595230eedea355eeabd4b2c25517f90fc868b23b1ea59663ad29", "derp", {js:{msg:"FFFF"}}, function(err, packet, chan){
		if(err) return console.log('START ERROR: ',err);
		console.log(packet);
		console.log(chan);
	})
});