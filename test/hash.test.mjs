import { test } from 'node:test';
import assert from 'node:assert/strict';
import { md5, sha1, sha256 } from '../src/core/hash.js';

test('md5 vectors', () => {
  assert.equal(md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5('abc'), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(md5('The quick brown fox jumps over the lazy dog'), '9e107d9d372bb6826bd81d3542a419d6');
  assert.equal(md5('a'.repeat(1000)), 'cabe45dcc9ae5b66ba86600cca6b8ba8');
});
test('sha1 vectors', () => {
  assert.equal(sha1(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.equal(sha1('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(sha1('a'.repeat(1000)), '291e9a6c66994949b57ba5e650361e98fc36b1ba');
});
test('sha256 vectors', () => {
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('a'.repeat(1000)), '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
});
