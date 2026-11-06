const assert = require("assert");
const { ethers } = require("hardhat");

const ROOT_A = "0x" + "aa".repeat(32);
const ROOT_B = "0x" + "bb".repeat(32);
const ZERO = "0x" + "00".repeat(32);

async function expectRevert(promise, reason) {
  try {
    await promise;
  } catch (err) {
    assert.ok(err.message.includes(reason), `expected revert "${reason}" but got: ${err.message}`);
    return;
  }
  assert.fail(`expected a revert with "${reason}" but the call succeeded`);
}

describe("LogAnchor", function () {
  let anchor, owner, stranger;

  beforeEach(async function () {
    [owner, stranger] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("LogAnchor");
    anchor = await Factory.deploy();
    await anchor.waitForDeployment();
  });

  it("makes the deployer the owner", async function () {
    assert.strictEqual(await anchor.owner(), owner.address);
  });

  it("stores a root and returns it with a timestamp", async function () {
    await anchor.anchorRoot(1, ROOT_A);
    const [root, ts] = await anchor.getRoot(1);
    assert.strictEqual(root, ROOT_A);
    assert.ok(ts > 0n);
  });

  it("returns an empty root for a batch that was never anchored", async function () {
    const [root, ts] = await anchor.getRoot(42);
    assert.strictEqual(root, ZERO);
    assert.strictEqual(ts, 0n);
  });

  it("emits a RootAnchored event", async function () {
    const tx = await anchor.anchorRoot(5, ROOT_A);
    const receipt = await tx.wait();
    const event = receipt.logs.map((l) => anchor.interface.parseLog(l)).find((e) => e && e.name === "RootAnchored");
    assert.ok(event, "RootAnchored event not found");
    assert.strictEqual(event.args.batchId, 5n);
    assert.strictEqual(event.args.merkleRoot, ROOT_A);
  });

  it("is WRITE-ONCE: a second anchor for the same batch reverts", async function () {
    await anchor.anchorRoot(1, ROOT_A);
    await expectRevert(anchor.anchorRoot(1, ROOT_B), "batch already anchored");
    assert.strictEqual((await anchor.getRoot(1))[0], ROOT_A); // original is untouched
  });

  it("only lets the owner anchor", async function () {
    await expectRevert(anchor.connect(stranger).anchorRoot(1, ROOT_A), "only owner can anchor");
  });

  it("rejects an all-zero root", async function () {
    await expectRevert(anchor.anchorRoot(1, ZERO), "empty root");
  });

  it("tracks the highest batch id even when anchored out of order", async function () {
    await anchor.anchorRoot(7, ROOT_A);
    await anchor.anchorRoot(3, ROOT_B);
    assert.strictEqual(await anchor.lastBatchId(), 7n);
  });
});
