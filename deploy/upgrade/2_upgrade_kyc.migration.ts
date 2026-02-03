import { Deployer } from "@solarity/hardhat-migrate";
import { ethers } from "hardhat";

import { KYCRegistryMock__factory } from "@ethers-v6";

const KYC_REGISTRY_PROXY = "0x6ae5cC9957c61Ec4e3e4CA7dFE371caa8cFFc9eB";

export = async (deployer: Deployer) => {
  const [signer] = await ethers.getSigners();
  const kyc = KYCRegistryMock__factory.connect(KYC_REGISTRY_PROXY, signer);

  const kycImpl = await deployer.deploy(KYCRegistryMock__factory);

  await kyc.upgradeToAndCall(await kycImpl.getAddress(), "0x");

  console.log("KYCRegistryMock upgraded to:", await kycImpl.getAddress());
};
