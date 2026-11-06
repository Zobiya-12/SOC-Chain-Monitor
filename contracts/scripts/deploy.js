const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  if (hre.network.name === "hardhat") {
    console.log("You ran this on Hardhat's temporary in-process network, which disappears when the");
    console.log("script ends. Start `npx hardhat node` and add:  --network localhost");
    process.exitCode = 1;
    return;
  }

  const [deployer] = await hre.ethers.getSigners();
  const network = await hre.ethers.provider.getNetwork();
  console.log(`Deploying LogAnchor to '${hre.network.name}' (chain ${network.chainId}) from ${deployer.address}`);

  const Factory = await hre.ethers.getContractFactory("LogAnchor");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();

  // The Python backend reads this file to find the contract (and checks chainId matches).
  const out = {
    address,
    network: hre.network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(__dirname, "..", "deployment.json"), JSON.stringify(out, null, 2));
  console.log("LogAnchor deployed to:", address);
  console.log("Saved to contracts/deployment.json");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
