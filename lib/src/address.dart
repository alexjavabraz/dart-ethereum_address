import "dart:convert";
import "dart:typed_data";

import "package:convert/convert.dart" show hex;
import 'package:pointycastle/digests/keccak.dart';

import "util.dart";

const HEX_PREFIX = '0x';

/// Derives an Ethereum address from a given public key.
String ethereumAddressFromPublicKey(Uint8List publicKey) {
  final decompressedPubKey = decompressPublicKey(publicKey);
  final hash = KeccakDigest(256).process(decompressedPubKey.sublist(1));
  final address = hash.sublist(12, 32);

  return checksumEthereumAddress(hex.encode(address));
}

/// Converts an Ethereum address to a checksummed address (EIP-55).
String checksumEthereumAddress(String address) {
  if (!isValidFormat(address)) {
    throw ArgumentError.value(address, "address", "invalid address");
  }

  final addr = strip0x(address).toLowerCase();
  final hash = ascii.encode(hex.encode(
    KeccakDigest(256).process(ascii.encode(addr)),
  ));

  var newAddr = HEX_PREFIX;

  for (var i = 0; i < addr.length; i++) {
    if (hash[i] >= 56) {
      newAddr += addr[i].toUpperCase();
    } else {
      newAddr += addr[i];
    }
  }

  return newAddr;
}

/// Returns whether a given Ethereum address is valid.
bool isValidEthereumAddress(String address) {
  if (!isValidFormat(address)) {
    return false;
  }

  final addr = strip0x(address);
  // if all lowercase or all uppercase, as in checksum is not present
  if (RegExp(r"^[0-9a-f]{40}$").hasMatch(addr) ||
      RegExp(r"^[0-9A-F]{40}$").hasMatch(addr)) {
    return true;
  }

  String checksumAddress;
  try {
    checksumAddress = checksumEthereumAddress(address);
  } catch (err) {
    return false;
  }

  return addr == checksumAddress.substring(2);
}

 String stripHexPrefix(String str) {
  if (str is! String) {
    throw ArgumentError('str is not a string');
  }
  return hasHexPrefix(str) ? str.substring(HEX_PREFIX.length) : str;
}
bool hasHexPrefix(String str) {
  if (str is! String) {
    throw ArgumentError('str is not a string');
  }
  return str.startsWith(HEX_PREFIX);
}

bool isHexPrefix(String str) {
  if (str is! String) {
    throw ArgumentError('str is not a string');
  }

  return str.startsWith(HEX_PREFIX);
}

/// Converts an address to a checksummed address (EIP-55).
String toChecksumAddress(String address, int chainId) {
  address = stripHexPrefix(address).toLowerCase();
  final prefix = (chainId != null) ? '${chainId.toString()}0x' : '';
  final hash =  hex.encode(
    KeccakDigest(256).process(ascii.encode('$prefix$address')),
  ).toString();

  return HEX_PREFIX +
      address.split('').asMap().entries.map((entry) {
        final b = entry.value;
        final i = entry.key;
        final hashCar = int.parse(hash[i], radix: 16);
        return hashCar >= 8 ? b.toUpperCase() : b;
      }).join('');
}

bool isAddress(String address) {
  return RegExp(r"^(0x)?[0-9a-fA-F]{40}$").hasMatch(address);
}

bool isValidChecksumAddress(String address, int chainId) {
  return isAddress(address) && toChecksumAddress(address, chainId) == address;
}
