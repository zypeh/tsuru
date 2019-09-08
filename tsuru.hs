module Main(main) where

-- import           Control.Monad.Extra  (ifM)
import           Data.Binary.Get      (Get, getWord16be, getWord32le, runGet,
                                       skip)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Word            as W
import           GHC.Int              (Int64)
import           System.Environment   (getArgs)

main :: IO ()
main = do
    args <- getArgs
    parseArgs args
    where
        parseArgs [pcapFileName] = readPcapFile pcapFileName
        parseArgs []             = putStrLn "No input. Exit now."
        parseArgs _              = putStrLn "unimplemented"


pcapGlobalHeaderLen :: Int64
pcapGlobalHeaderLen = 24

-- pcapHeaderLen :: Int64
-- pcapHeaderLen = 32

-- udpHeaderLen :: Int64
-- udpHeaderLen = 8

ethernetIPv4HeaderLen :: Int
ethernetIPv4HeaderLen = 14 + 20

data PcapHeader = PcapHeader
  { pcapTimestampSec  :: {-# UNPACK #-} !W.Word32
  , pcapTimestampUsec :: {-# UNPACK #-} !W.Word32
  , pcapCaptureLen    :: {-# UNPACK #-} !W.Word32
  , pcapWireLen       :: {-# UNPACK #-} !W.Word32
  } deriving (Show)

getPcapHeader :: Get PcapHeader
getPcapHeader = let consume = getWord32le in
    PcapHeader <$> consume <*> consume <*> consume <*> consume

data UdpHeader = UdpHeader
  { udpSrcPort    :: {-# UNPACK #-} !W.Word16
  , udpDestPort   :: {-# UNPACK #-} !W.Word16
  , udpPayloadLen :: {-# UNPACK #-} !W.Word16
  , udpCheckSum   :: {-# UNPACK #-} !W.Word16
  } deriving (Show)

getUdpHeader :: Get UdpHeader
getUdpHeader = let consume = getWord16be in
    UdpHeader <$> consume <*> consume <*> consume <*> consume

readPcapFile :: String -> IO ()
readPcapFile fileName = do
    pcap <- BL.readFile fileName
    -- print . BL.unpack $ BL.take 500 content

    -- https://wiki.wireshark.org/Development/LibpcapFileFormat
    let payloadWithoutPcapGlobalHeader = BL.drop pcapGlobalHeaderLen $ BL.take 500 pcap

    print $ runGet getPcapHeader payloadWithoutPcapGlobalHeader
    runGet getMarketData payloadWithoutPcapGlobalHeader -- should recursively read packets here


getMarketData :: Get (IO ())
getMarketData = do
    pcapHeader <- getPcapHeader
    let packetLen = fromIntegral $ pcapCaptureLen pcapHeader :: Int

    if packetLen <= 0
        then do
            skip packetLen
            return $ print packetLen
        else do
            skip ethernetIPv4HeaderLen
            -- take
            print <$> getUdpHeader
