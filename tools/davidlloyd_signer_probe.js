import Java from 'frida-java-bridge';

'use strict';

/*
 * Privacy-preserving Frida probe for the David Lloyd Android request signer.
 * It never reads or prints key bytes, MAC bytes, tokens, passwords, or raw
 * request bodies. Runtime instrumentation only; no request is modified.
 */

Java.perform(function () {
  const System = Java.use('java.lang.System');
  const Thread = Java.use('java.lang.Thread');

  function emit(kind, fields) {
    fields.kind = kind;
    fields.time = Date.now();
    send(fields);
  }

  function className(value) {
    try {
      return value === null ? null : value.getClass().getName().toString();
    } catch (_) {
      return null;
    }
  }

  function keyMetadata(key) {
    if (key === null) {
      return { keyAlgorithm: null, keyClass: null, keyFormat: null };
    }
    let format = null;
    try {
      const candidate = key.getFormat();
      format = candidate === null ? null : candidate.toString();
    } catch (_) {}
    return {
      keyAlgorithm: key.getAlgorithm().toString(),
      keyClass: className(key),
      keyFormat: format,
    };
  }

  function stack() {
    const frames = Thread.currentThread().getStackTrace();
    const result = [];
    for (let i = 0; i < frames.length && result.length < 14; i++) {
      const text = frames[i].toString();
      if (!/^(java\.|javax\.|android\.|com\.android\.|dalvik\.|sun\.|org\.chromium\.)/.test(text)) {
        result.push(text);
      }
    }
    return result;
  }

  function bytesSlice(value, offset, length) {
    const out = [];
    if (value === null) return out;
    const start = offset || 0;
    const end = Math.min(value.length, start + (length === undefined ? value.length : length));
    for (let i = start; i < end; i++) out.push(value[i] & 0xff);
    return out;
  }

  function safePreview(bytes) {
    let text = '';
    const limit = Math.min(bytes.length, 2048);
    for (let i = 0; i < limit; i++) {
      const b = bytes[i];
      if (b === 10) text += '\\n';
      else if (b === 13) text += '\\r';
      else if (b === 9) text += '\\t';
      else text += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }

    // Remove values while retaining separators, field names, and ordering.
    text = text.replace(/("[^"\\]{1,80}"\s*:\s*)"(?:[^"\\]|\\.)*"/g, '$1"<redacted>"');
    text = text.replace(/([?&][A-Za-z0-9_.-]{1,80}=)[^&\s]+/g, '$1<redacted>');
    text = text.replace(/[A-Za-z0-9+\/_=-]{20,}/g, '<blob>');
    text = text.replace(/\d{3,}/g, '<number>');
    return text.slice(0, 768);
  }

  function componentShapes(bytes) {
    const components = [];
    let current = [];
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 10) {
        components.push(current);
        current = [];
      } else {
        current.push(bytes[i]);
      }
    }
    components.push(current);
    return components.map(function (component) {
      return { length: component.length, shape: safePreview(component) };
    });
  }

  const macState = Object.create(null);
  const Mac = Java.use('javax.crypto.Mac');

  function macId(instance) {
    return String(System.identityHashCode(instance));
  }

  function stateFor(instance) {
    const id = macId(instance);
    if (!(id in macState)) {
      macState[id] = { segments: [], totalLength: 0 };
    }
    return macState[id];
  }

  const macInit = Mac.init.overload('java.security.Key');
  macInit.implementation = function (key) {
    const result = macInit.call(this, key);
    const id = macId(this);
    macState[id] = { segments: [], totalLength: 0 };
    emit('mac-init', Object.assign({
      id: id,
      algorithm: this.getAlgorithm().toString(),
      provider: this.getProvider().getName().toString(),
      stack: stack(),
    }, keyMetadata(key)));
    return result;
  };

  try {
    const macInitParams = Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
    macInitParams.implementation = function (key, params) {
      const result = macInitParams.call(this, key, params);
      const id = macId(this);
      macState[id] = { segments: [], totalLength: 0 };
      emit('mac-init', Object.assign({
        id: id,
        algorithm: this.getAlgorithm().toString(),
        provider: this.getProvider().getName().toString(),
        parameterClass: className(params),
        stack: stack(),
      }, keyMetadata(key)));
      return result;
    };
  } catch (_) {}

  const macUpdateBytes = Mac.update.overload('[B');
  macUpdateBytes.implementation = function (input) {
    const bytes = bytesSlice(input);
    const state = stateFor(this);
    state.segments.push(bytes);
    state.totalLength += bytes.length;
    return macUpdateBytes.call(this, input);
  };

  const macUpdateRange = Mac.update.overload('[B', 'int', 'int');
  macUpdateRange.implementation = function (input, offset, length) {
    const bytes = bytesSlice(input, offset, length);
    const state = stateFor(this);
    state.segments.push(bytes);
    state.totalLength += bytes.length;
    return macUpdateRange.call(this, input, offset, length);
  };

  function finishMac(instance, outputLength) {
    const id = macId(instance);
    const state = stateFor(instance);
    const combined = [];
    const segmentLengths = [];
    state.segments.forEach(function (segment) {
      segmentLengths.push(segment.length);
      Array.prototype.push.apply(combined, segment);
    });
    emit('mac-final', {
      id: id,
      algorithm: instance.getAlgorithm().toString(),
      inputLength: state.totalLength,
      segmentLengths: segmentLengths,
      components: componentShapes(combined),
      inputShape: safePreview(combined),
      outputLength: outputLength,
      stack: stack(),
    });
    macState[id] = { segments: [], totalLength: 0 };
  }

  const macDoFinal = Mac.doFinal.overload();
  macDoFinal.implementation = function () {
    const output = macDoFinal.call(this);
    finishMac(this, output === null ? null : output.length);
    return output;
  };

  const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  const secretKeyInit = SecretKeySpec.$init.overload('[B', 'java.lang.String');
  secretKeyInit.implementation = function (keyBytes, algorithm) {
    const result = secretKeyInit.call(this, keyBytes, algorithm);
    const name = algorithm === null ? '' : algorithm.toString();
    if (name.toLowerCase().indexOf('hmac') !== -1) {
      emit('secret-key-spec', {
        algorithm: name,
        keyLength: keyBytes === null ? null : keyBytes.length,
        stack: stack(),
      });
    }
    return result;
  };

  try {
    const MessageDigest = Java.use('java.security.MessageDigest');
    const digestBytes = MessageDigest.digest.overload('[B');
    digestBytes.implementation = function (input) {
      const output = digestBytes.call(this, input);
      const frames = stack();
      if (frames.some(function (frame) {
        return frame.indexOf('ao.i.') !== -1 || frame.indexOf('T8.b.') !== -1;
      })) {
        const bytes = bytesSlice(input);
        emit('message-digest', {
          algorithm: this.getAlgorithm().toString(),
          inputLength: bytes.length,
          inputShape: safePreview(bytes),
          outputLength: output === null ? null : output.length,
          stack: frames,
        });
      }
      return output;
    };
  } catch (error) {
    emit('hook-warning', { target: 'java.security.MessageDigest.digest', error: String(error) });
  }

  const Cipher = Java.use('javax.crypto.Cipher');
  const cipherState = Object.create(null);
  function cipherId(instance) {
    return String(System.identityHashCode(instance));
  }
  const cipherInit = Cipher.init.overload('int', 'java.security.Key');
  cipherInit.implementation = function (mode, key) {
    const result = cipherInit.call(this, mode, key);
    const transformation = this.getAlgorithm().toString();
    if (transformation.toUpperCase().indexOf('RSA') !== -1) {
      cipherState[cipherId(this)] = { mode: mode, transformation: transformation };
      emit('rsa-cipher-init', Object.assign({
        id: cipherId(this),
        mode: mode,
        transformation: transformation,
        provider: this.getProvider().getName().toString(),
        stack: stack(),
      }, keyMetadata(key)));
    }
    return result;
  };

  const cipherFinalBytes = Cipher.doFinal.overload('[B');
  cipherFinalBytes.implementation = function (input) {
    const output = cipherFinalBytes.call(this, input);
    const id = cipherId(this);
    if (id in cipherState) {
      emit('rsa-cipher-final', {
        id: id,
        transformation: cipherState[id].transformation,
        inputLength: input === null ? null : input.length,
        outputLength: output === null ? null : output.length,
        stack: stack(),
      });
    }
    return output;
  };

  try {
    const KeyStore = Java.use('java.security.KeyStore');
    const getKey = KeyStore.getKey.overload('java.lang.String', '[C');
    getKey.implementation = function (alias, password) {
      const key = getKey.call(this, alias, password);
      const rawAlias = alias === null ? '' : alias.toString();
      emit('keystore-get-key', Object.assign({
        storeType: this.getType().toString(),
        aliasShape: rawAlias.length <= 24 ? rawAlias : '<redacted-long-alias>',
        aliasLength: rawAlias.length,
        stack: stack(),
      }, keyMetadata(key)));
      return key;
    };
  } catch (error) {
    emit('hook-warning', { target: 'java.security.KeyStore.getKey', error: String(error) });
  }

  try {
    const Builder = Java.use('okhttp3.Request$Builder');
    ['header', 'addHeader'].forEach(function (methodName) {
      const method = Builder[methodName].overload('java.lang.String', 'java.lang.String');
      method.implementation = function (name, value) {
        const normalized = name === null ? '' : name.toString().toLowerCase();
        if (normalized === 'x-signature' || normalized === 'x-timestamp') {
          emit('signature-header-added', {
            header: normalized,
            valueLength: value === null ? null : value.toString().length,
            stack: stack(),
          });
        }
        return method.call(this, name, value);
      };
    });
  } catch (error) {
    emit('hook-warning', { target: 'okhttp3.Request$Builder', error: String(error) });
  }

  emit('probe-ready', { pid: Process.id });
});
