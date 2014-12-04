(function($){

    var gen_from = 'pass';
    var gen_compressed = true;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 600;
    var timeout = null;

    var PUBLIC_KEY_VERSION = 85;
    var PRIVATE_KEY_VERSION = 213;
    var OLD_PRIVATE_KEY_VERSION = 73;
    var ADDRESS_URL_PREFIX = 'http://bitmark.co:3000'

    function parseBase58Check(address) {
        var bytes = Bitcoin.Base58.decode(address);
        var end = bytes.length - 4;
        var hash = bytes.slice(0, end);
        var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
        if (checksum[0] != bytes[end] ||
            checksum[1] != bytes[end+1] ||
            checksum[2] != bytes[end+2] ||
            checksum[3] != bytes[end+3])
                throw new Error("Wrong checksum");
        var version = hash.shift();
        return [version, hash];
    }

    encode_length = function(len) {
        if (len < 0x80)
            return [len];
        else if (len < 255)
            return [0x80|1, len];
        else
            return [0x80|2, len >> 8, len & 0xff];
    }
    
    encode_id = function(id, s) {
        var len = encode_length(s.length);
        return [id].concat(len).concat(s);
    }

    encode_integer = function(s) {
        if (typeof s == 'number')
            s = [s];
        return encode_id(0x02, s);
    }

    encode_octet_string = function(s)  {
        return encode_id(0x04, s);
    }

    encode_constructed = function(tag, s) {
        return encode_id(0xa0 + tag, s);
    }

    encode_bitstring = function(s) {
        return encode_id(0x03, s);
    }

    encode_sequence = function() {
        sequence = [];
        for (var i = 0; i < arguments.length; i++)
            sequence = sequence.concat(arguments[i]);
        return encode_id(0x30, sequence);
    }

    function getEncoded(pt, compressed) {
       var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
       return enc;
    }

    function getDER(eckey, compressed) {
        var curve = getSECCurveByName("secp256k1");
        var _p = curve.getCurve().getQ().toByteArrayUnsigned();
        var _r = curve.getN().toByteArrayUnsigned();
        var encoded_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

        var secret = integerToBytes(eckey.priv, 32);
        var encoded_gxgy = getEncoded(curve.getG(), compressed);
        var encoded_pub = getEncoded(gen_pt, compressed);

        return encode_sequence(
            encode_integer(1),
            encode_octet_string(secret),
            encode_constructed(0,
                encode_sequence(
                    encode_integer(1),
                    encode_sequence(
                        encoded_oid, //encode_oid(*(1, 2, 840, 10045, 1, 1)), //TODO
                        encode_integer([0].concat(_p))
                    ),
                    encode_sequence(
                        encode_octet_string([0]),
                        encode_octet_string([7])
                    ),
                    encode_octet_string(encoded_gxgy),
                    encode_integer([0].concat(_r)),
                    encode_integer(1)
                )
            ),
            encode_constructed(1, 
                encode_bitstring([0].concat(encoded_pub))
            )
        );
    }

    function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }

    function setErrorState(field, err, msg) {
        var group = field.closest('.controls');
        if (err) {
            group.addClass('has-error');
            group.attr('title',msg);
        } else {
            group.removeClass('has-error');
            group.attr('title','');
        }
    }

    function genRandom() {
        $('#pass').val('');
        $('#hash').focus();
        gen_from = 'hash';
        $('#from_hash').click();
        update_gen();
        var bytes = Crypto.util.randomBytes(32);
        $('#hash').val(Crypto.util.bytesToHex(bytes));
        generate();
    }

    function update_gen() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        $('#pass').attr('readonly', gen_from != 'pass');
        $('#hash').attr('readonly', gen_from != 'hash');
        $('#sec').attr('readonly', gen_from != 'sec');
        $('#seco').attr('readonly', gen_from != 'seco');
        $('#sec').parent().parent().removeClass('error');
    }

    function update_gen_from() {
        gen_from = $(this).attr('id').substring(5);
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
            $('#pass').focus();
        } else if (gen_from == 'hash') {
            $('#hash').focus();
        } else if (gen_from == 'sec') {
            $('#sec').focus();
        } else if (gen_from == 'seco') {
            $('#seco').focus();
        }
    }

    function update_gen_from_focus() {
        gen_from = $(this).attr('id');
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
        }
        $('#from_'+gen_from).button('toggle');
    }

    function generate() {
        var hash_str = pad($('#hash').val(), 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);
        eckey = new Bitcoin.ECKey(hash);
        gen_eckey = eckey;

        try {
            var curve = getSECCurveByName("secp256k1");
            gen_pt = curve.getG().multiply(eckey.priv);
            gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
            gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
            setErrorState($('#hash'), false);
        } catch (err) {
            //console.info(err);
            setErrorState($('#hash'), true, 'Invalid secret exponent (must be non-zero value)');
            return;
        }

        gen_update();
    }

    function genOnChangeCompressed() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        gen_compressed = $(this).attr('name') == 'compressed';
        gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        gen_update();
    }

    function gen_update() {

        var eckey = gen_eckey;
        var compressed = gen_compressed;

        var hash_str = pad($('#hash').val(), 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);

        var hash160 = eckey.getPubKeyHash();

        var h160 = Crypto.util.bytesToHex(hash160);
        $('#h160').val(h160);

        var addr = new Bitcoin.Address(hash160);
        addr.version = PUBLIC_KEY_VERSION;
        $('#addr').val(addr);

        var payload = hash;

        if (compressed)
            payload.push(0x01);

        var sec = new Bitcoin.Address(payload);
        sec.version = PRIVATE_KEY_VERSION;
        $('#sec').val(sec);
        
        var seco = new Bitcoin.Address(payload);
        seco.version = OLD_PRIVATE_KEY_VERSION;
        $('#seco').val(seco);

        var pub = Crypto.util.bytesToHex(getEncoded(gen_pt, compressed));
        $('#pub').val(pub);

        var der = Crypto.util.bytesToHex(getDER(eckey, compressed));
        $('#der').val(der);

        var qrCode = qrcode(3, 'M');
        var text = $('#addr').val();
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        qrCode.addData(text);
        qrCode.make();

        $('#genAddrQR').html(qrCode.createImgTag(4));
        $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+'/address/'+addr);
        $('#genAddrURL').attr('title', addr);

        // NMC fix
        if (ADDRESS_URL_PREFIX.indexOf('explorer.dot-bit.org')>=0 )
          $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+'/a/'+addr);

        // chainbrowser fix (needs closing slash for some reason)
        if (ADDRESS_URL_PREFIX.indexOf('chainbrowser.com')>=0 )
          $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+'/address/'+addr+'/');
    }


    function calc_hash() {
        var hash = Crypto.SHA256($('#pass').val(), { asBytes: true });
        $('#hash').val(Crypto.util.bytesToHex(hash));
    }

    function onChangePass() {
        calc_hash();
        clearTimeout(timeout);
        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangeHash() {
        $('#pass').val('');
        gen_ps_reset = true;
        clearTimeout(timeout);

        if (/[^0123456789abcdef]+/i.test($('#hash').val())) {
            setErrorState($('#hash'), true, 'Erroneous characters (must be 0..9-a..f)');
            return;
        } else {
            setErrorState($('#hash'), false);
        }

        timeout = setTimeout(generate, TIMEOUT);
    }

    function genOnChangePrivKey() {

        clearTimeout(timeout);

        $('#pass').val('');
        gen_ps_reset = true;

        var sec = $('#sec').val();

        try { 
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            setErrorState($('#sec'), true, 'Invalid private key checksum');
            return;
        };

        if (version != PRIVATE_KEY_VERSION) {
            setErrorState($('#sec'), true, 'Invalid private key version');
            return;
        } else if (payload.length < 32) {
            setErrorState($('#sec'), true, 'Invalid payload (must be 32 or 33 bytes)');
            return;
        }

        setErrorState($('#sec'), false);

        if (payload.length > 32) {
            payload.pop();
            gen_compressed = true;
        } else {
            gen_compressed = false;
        }

        // toggle radio button without firing an event
        $('#gen_comp label input').off();
        $('#gen_comp label input[name='+(gen_compressed?'compressed':'uncompressed')+']').click();
        $('#gen_comp label input').on('change', genOnChangeCompressed);

        $('#hash').val(Crypto.util.bytesToHex(payload));

        timeout = setTimeout(generate, TIMEOUT);
    }

    function genOnChangeOldPrivKey() {

      clearTimeout(timeout);

      $('#pass').val('');
      gen_ps_reset = true;

      var seco = $('#seco').val();

      try { 
          var res = parseBase58Check(seco); 
          var version = res[0];
          var payload = res[1];
      } catch (err) {
          setErrorState($('#seco'), true, 'Invalid private key checksum');
          return;
      };

      if (version != OLD_PRIVATE_KEY_VERSION) {
          setErrorState($('#seco'), true, 'Invalid private key version');
          return;
      } else if (payload.length < 32) {
          setErrorState($('#seco'), true, 'Invalid payload (must be 32 or 33 bytes)');
          return;
      }

      setErrorState($('#seco'), false);

      if (payload.length > 32) {
          payload.pop();
          gen_compressed = true;
      } else {
          gen_compressed = false;
      }

      // toggle radio button without firing an event
      $('#gen_comp label input').off();
      $('#gen_comp label input[name='+(gen_compressed?'compressed':'uncompressed')+']').click();
      $('#gen_comp label input').on('change', genOnChangeCompressed);

      $('#hash').val(Crypto.util.bytesToHex(payload));

      timeout = setTimeout(generate, TIMEOUT);
  }
    
    function genRandomPass() {
        // chosen by fair dice roll
        // guaranted to be random
        $('#from_pass').button('toggle');
        $('#pass').focus();
        gen_from = 'pass';
        update_gen();
        calc_hash();
        generate();
    }

    function onInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }


    $(document).ready( function() {

        onInput('#pass', onChangePass);
        onInput('#hash', onChangeHash);
        onInput('#sec', genOnChangePrivKey);
        onInput('#seco', genOnChangeOldPrivKey);
        
        $('#genRandom').click(genRandom);

        $('#gen_from label input').on('change', update_gen_from );
        $('#gen_comp label input').on('change', genOnChangeCompressed);

        genRandomPass();

    });
})(jQuery);
