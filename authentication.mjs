/**
 * This does a look-up in the account collection
 * Addresses are case-insensitive, so we normalize to lowercase for comparison
 *
 * @param clientInfo
 * @returns {boolean}
 */
export async function accountList(connector,clientInfo) {
  // Normalize address to lowercase for direct matching (all addresses stored lowercase)
  const normalizedAddress = clientInfo.address.toLowerCase();
  let users = await connector.db.collection("user").find({
    address: normalizedAddress
  }).toArray();
  return (users.length > 0) ? users[0] : null;
}

/**
 * This is intended to reference an in contract white list. It ultimately belongs
 * in a shared project or part of the root epistery code.
 *
 * @param clientInfo
 * @returns {boolean}
 */
export async function whiteList(clientInfo) {
  return true
}

/**
 * This is intended to control access based on token holdings
 * This also belongs in a shared library
 *
 * @param token - Token symbol (e.g., 'BTC', 'RVT') or contract address for ERC-20 tokens
 * @param apiKey - Etherscan API key (optional, uses V1 API if not provided)
 * @param clientInfo - Object containing address, chainId, lookupUrl
 * @returns {boolean}
 */
export async function TokenHolder(token, apiKey, clientInfo) {
  try {
    const address = clientInfo.address;
    const chainId = clientInfo.chainId || 1; // Default to Ethereum mainnet
    const lookupUrl = clientInfo.lookupUrl || 'etherscan.io';

    if (!address || !token) {
      console.warn('TokenHolder: Missing required address or token');
      return false;
    }

    // Only support etherscan.io for now
    if (!lookupUrl.includes('etherscan.io')) {
      console.warn(`TokenHolder: Unsupported lookup URL: ${lookupUrl}`);
      return false;
    }

    // Handle native tokens vs ERC-20 tokens
    if (token.toUpperCase() === 'ETH') {
      return await checkEthBalance(address, apiKey);
    } else {
      // Assume it's an ERC-20 token - could be symbol or contract address
      return await checkERC20Balance(address, token, apiKey);
    }

  } catch (error) {
    console.error('TokenHolder error:', error);
    return false;
  }
}

/**
 * Check ETH balance using Etherscan API
 */
async function checkEthBalance(address, apiKey) {
  try {
    // Use V2 API if apiKey provided, otherwise fall back to V1
    const apiUrl = apiKey
      ? `https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address=${address}&tag=latest&apikey=${apiKey}`
      : `https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest`;

    const response = await fetch(apiUrl);
    const data = await response.json();

    if (data.status === '1') {
      const balanceWei = BigInt(data.result);
      const balanceEth = Number(balanceWei) / 1e18;

      console.log(`[debug] ETH balance for ${address}: ${balanceEth} ETH`);
      // Return true if balance > 0
      return balanceEth > 0;
    }

    console.log(`[debug] ETH balance check failed for ${address}:`, data);
    return false;
  } catch (error) {
    console.error('Error checking ETH balance:', error);
    return false;
  }
}

/**
 * Check ERC-20 token balance using Etherscan API
 */
async function checkERC20Balance(address, token, apiKey) {
  try {
    // If token looks like a contract address (starts with 0x and 42 chars), use it directly
    const contractAddress = token.startsWith('0x') && token.length === 42
      ? token
      : await getTokenContractAddress(token);

    if (!contractAddress) {
      console.warn(`TokenHolder: Could not find contract address for token: ${token}`);
      return false;
    }

    console.log(`[debug] Checking ${token} balance for ${address} using contract ${contractAddress}`);

    // Use V2 API if apiKey provided, otherwise fall back to V1
    const apiUrl = apiKey
      ? `https://api.etherscan.io/v2/api?chainid=1&module=account&action=tokenbalance&contractaddress=${contractAddress}&address=${address}&tag=latest&apikey=${apiKey}`
      : `https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=${contractAddress}&address=${address}&tag=latest`;

    const response = await fetch(apiUrl);
    const data = await response.json();

    console.log(`[debug] Etherscan API response:`, data);

    if (data.status === '1') {
      const balance = BigInt(data.result);
      const balanceFormatted = Number(balance) / 1e18; // Assuming 18 decimals - might need adjustment

      console.log(`[debug] ${token} balance for ${address}: ${balance} raw (${balanceFormatted} formatted)`);

      // Return true if balance > 0
      return balance > 0n;
    }

    console.log(`[debug] Token balance check failed for ${address}:`, data);
    return false;
  } catch (error) {
    console.error('Error checking ERC-20 balance:', error);
    return false;
  }
}

/**
 * Get contract address for a token symbol (simplified - in practice would need a token registry)
 */
async function getTokenContractAddress(tokenSymbol) {
  // Common token contract addresses on Ethereum mainnet
  const knownTokens = {
    'USDC': '0xA0b86a33E6441E7a15BFF433b3c5b8bE5dE36b79',
    'USDT': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    'WBTC': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
    'LINK': '0x514910771AF9Ca656af840dff83E8264EcF986CA',
    'UNI': '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
    // RVT token - this might need to be updated with the actual contract address
    'RVT': '0x3d1ba9be9f66b8ee101911bc36d3fb562eac2244',
    // Add more tokens as needed
  };

  console.log(`[debug] Looking up contract address for token: ${tokenSymbol.toUpperCase()}`);
  const address = knownTokens[tokenSymbol.toUpperCase()];
  console.log(`[debug] Found contract address: ${address}`);

  return address || null;
}
