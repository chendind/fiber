import time, httpx, asyncio

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, Header

from fiber import constants as cst
from fiber.encrypted.miner.core.configuration import Config
from fiber.encrypted.miner.core.models.encryption import PublicKeyResponse, SymmetricKeyExchange
from fiber.encrypted.miner.dependencies import blacklist_low_stake, get_config, verify_request
from fiber.encrypted.miner.security.encryption import get_symmetric_key_b64_from_payload
from fiber.logging_utils import get_logger

from taocd.db_manager import HOST_IP, load_miner_servers

logger = get_logger(__name__)


async def get_public_key(config: Config = Depends(get_config)):
    public_key = config.encryption_keys_handler.public_bytes.decode()
    return PublicKeyResponse(
        public_key=public_key,
        timestamp=time.time(),
    )

async def forward_request_to_servers(payload: SymmetricKeyExchange, headers: dict):
    """
    将请求转发到目标服务器
    """
    async with httpx.AsyncClient() as client:
        tasks = []
        miner_servers = load_miner_servers()
        targer_servers = [
            server for server in miner_servers
            if HOST_IP not in server
        ]
        for server in targer_servers:
            url = f"{server}/exchange-symmetric-key-async"
            tasks.append(client.post(url, json=payload.dict(), headers=headers))
        
        # 并发发送请求
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 检查响应
        for server, response in zip(targer_servers, responses):
            if isinstance(response, Exception):
                logger.error(f"Failed to forward request to {server}: {response}")
            elif response.status_code != 200:
                logger.error(f"Server {server} returned status code {response.status_code}: {response.text}")

async def exchange_symmetric_key(
    payload: SymmetricKeyExchange,
    validator_hotkey_address: str = Header(..., alias=cst.VALIDATOR_HOTKEY),
    miner_hotkey: str = Header(..., alias=cst.MINER_HOTKEY),
    signature: str = Header(..., alias=cst.SIGNATURE),
    nonce: str = Header(..., alias=cst.NONCE),
    symmetric_key_uuid: str = Header(..., alias=cst.SYMMETRIC_KEY_UUID),
    config: Config = Depends(get_config),
):
    logger.info(f"encrypted_symmetric_key={payload.encrypted_symmetric_key}")
    base64_symmetric_key = get_symmetric_key_b64_from_payload(payload, config.encryption_keys_handler.private_key)
    fernet = Fernet(base64_symmetric_key)
    config.encryption_keys_handler.add_symmetric_key(
        uuid=symmetric_key_uuid,
        hotkey_ss58_address=validator_hotkey_address,
        fernet=fernet,
    )

    try:
        # 转发请求到其他服务器
        headers = {
            cst.VALIDATOR_HOTKEY: validator_hotkey_address,
            cst.NONCE: nonce,
            cst.SYMMETRIC_KEY_UUID: symmetric_key_uuid,
            cst.MINER_HOTKEY: miner_hotkey,
            cst.SIGNATURE: signature
        }
        await forward_request_to_servers(payload, headers)
    except Exception as e:
        logger.error(f"Failed to forward request: {e}")

    return {"status": "Symmetric key exchanged successfully"}

async def exchange_symmetric_key_async(
    payload: SymmetricKeyExchange,
    validator_hotkey_address: str = Header(..., alias=cst.VALIDATOR_HOTKEY),
    nonce: str = Header(..., alias=cst.NONCE),
    symmetric_key_uuid: str = Header(..., alias=cst.SYMMETRIC_KEY_UUID),
    config: Config = Depends(get_config),
):
    base64_symmetric_key = get_symmetric_key_b64_from_payload(payload, config.encryption_keys_handler.private_key)
    fernet = Fernet(base64_symmetric_key)
    config.encryption_keys_handler.add_symmetric_key(
        uuid=symmetric_key_uuid,
        hotkey_ss58_address=validator_hotkey_address,
        fernet=fernet,
    )

    return {"status": "Symmetric key exchanged successfully"}

def factory_router() -> APIRouter:
    router = APIRouter(tags=["Handshake"])
    router.add_api_route("/public-encryption-key", get_public_key, methods=["GET"])
    router.add_api_route(
        "/exchange-symmetric-key",
        exchange_symmetric_key,
        methods=["POST"],
        dependencies=[
            Depends(blacklist_low_stake),
            Depends(verify_request),
        ],
    )
    router.add_api_route(
        "/exchange-symmetric-key-async",
        exchange_symmetric_key_async,
        methods=["POST"],
        dependencies=[
            Depends(blacklist_low_stake),
            Depends(verify_request),
        ],
    )
    return router
