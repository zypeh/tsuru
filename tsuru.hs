module Main(main) where

-- import           Control.Monad.Extra  (ifM)
import           Data.Binary.Get      (Get, getWord16le, getWord32le, runGet,
                                       skip)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Word            as W
import           System.Environment   (getArgs)

main :: IO ()
main = do
    args <- getArgs
    parseArgs args
    where
        parseArgs [pcapFileName] = readPcapFile pcapFileName
        parseArgs []             = putStrLn "No input. Exit now."
        parseArgs _              = putStrLn "unimplemented"

data PcapHeader = PcapHeader
  { pcapTimestampSec  :: !W.Word32
  , pcapTimestampUsec :: !W.Word32
  , pcapLen           :: !W.Word32
  , pcapOriginalLen   :: !W.Word32
  } deriving (Show)

getPcapHeader :: Get PcapHeader
getPcapHeader = let consume = getWord32le in
    PcapHeader <$> consume <*> consume <*> consume <*> consume

data UdpHeader = UdpHeader
  { udpSrcPort    :: !W.Word16
  , udpDestPort   :: !W.Word16
  , udpPayloadLen :: !W.Word16
  , udpCheckSum   :: !W.Word16
  } deriving (Show)

getUdpHeader :: Get UdpHeader
getUdpHeader = let consume = getWord16le in
    UdpHeader <$> consume <*> consume <*> consume <*> consume

readPcapFile :: String -> IO ()
readPcapFile fileName = do
    content <- BL.readFile fileName
    -- print . BL.unpack $ BL.take (4 * 32) content
    -- print $ runGet getPcapHeader $ BL.take (4 * 32) content
    runGet getMarketData $ BL.take 215 content -- 215 is the full length

-- getPcapHeaders :: Get [PcapHeader]
-- getPcapHeaders = ifM isEmpty (return []) $ do
--     x <- getPcapHeader
--     xs <- getPcapHeaders
--     return (x:xs)

getMarketData :: Get (IO ())
getMarketData = do
    pcapHeader <- getPcapHeader
    let packetLen = fromIntegral $ pcapLen pcapHeader
    if packetLen < 0
        then do
            skip packetLen
            return $ putStrLn "Zero length packet in pcap."
        else print <$> getUdpHeader
