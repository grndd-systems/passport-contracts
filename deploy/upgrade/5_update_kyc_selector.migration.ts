import { Deployer } from "@solarity/hardhat-migrate";
import { ethers } from "hardhat";

import { KYCRegistryMock__factory } from "@ethers-v6";

const KYC_REGISTRY_PROXY = "0x6ae5cC9957c61Ec4e3e4CA7dFE371caa8cFFc9eB";

export = async (_deployer: Deployer) => {
  const [signer] = await ethers.getSigners();
  const kyc = KYCRegistryMock__factory.connect(KYC_REGISTRY_PROXY, signer);

  const currentSelector = await kyc.selector();
  const newSelector = currentSelector & ~(1n << 17n);

  await kyc.updateSelector(newSelector);

  console.log(`Selector updated: ${currentSelector} -> ${newSelector} (bit 17 cleared)`);
};
