import { Deployer } from "@solarity/hardhat-migrate";
import { ethers } from "hardhat";

import { StateKeeperMock__factory } from "@ethers-v6";

const STATE_KEEPER_PROXY = "0x91784Fd7FCC9D557e24e180016F1377120661475";

export = async (deployer: Deployer) => {
  const [signer] = await ethers.getSigners();
  const stateKeeper = StateKeeperMock__factory.connect(STATE_KEEPER_PROXY, signer);

  const stateKeeperImpl = await deployer.deploy(StateKeeperMock__factory);

  await stateKeeper.upgradeToAndCall(await stateKeeperImpl.getAddress(), "0x");

  console.log("StateKeeperMock upgraded to:", await stateKeeperImpl.getAddress());
};
