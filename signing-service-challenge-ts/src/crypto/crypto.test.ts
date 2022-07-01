import { assert } from "chai";
import { generateKeyPair } from "./generation";
import { Algorithm, sign, verify } from "./signer";

describe("crypto", () => {
  it("test sign and verify with RSA key", async () => {
    const pair = await generateKeyPair(Algorithm.RSA);

    const signature = sign(Algorithm.RSA, "some data to sign", pair.private);

    assert.isTrue(
      verify(Algorithm.RSA, "some data to sign", signature, pair.public)
    );
  });

  it("test sign and verify with EC key", async () => {
    const pair = await generateKeyPair(Algorithm.EC);

    const signature = sign(Algorithm.EC, "some data to sign", pair.private);

    assert.isTrue(
      verify(Algorithm.EC, "some data to sign", signature, pair.public)
    );
  });
});
