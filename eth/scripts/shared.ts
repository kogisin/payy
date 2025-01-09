import hre from 'hardhat'
import { readFile } from 'fs/promises'

export async function deployBin(binFile: string): Promise<`0x${string}`> {
  const bin = (await readFile(`contracts/${binFile}`)).toString().trimEnd()

  // console.log('Deploying contract of size: ', bin.length / 2, 'bytes')

  const [owner] = await hre.viem.getWalletClients()
  const verifierTx = await owner.deployContract({
    account: owner.account,
    bytecode: `0x${bin}`,
    abi: []
  })

  const publicClient = await hre.viem.getPublicClient()
  const verifierAddr = (await publicClient.waitForTransactionReceipt({ hash: verifierTx })).contractAddress

  if (verifierAddr === null || verifierAddr === undefined) throw new Error('Verifier address not found')

  return verifierAddr
}
