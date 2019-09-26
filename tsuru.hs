module Main(main) where

import           Control.Monad.Extra  (ifM)
import           Data.Binary.Get      (Get, getWord16be, getWord32le, runGet,
                                       skip, getLazyByteString)
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
getPcapHeader = do
    timestampSec <- getWord32le
    timestampUsec <- getWord32le
    captureLen <- getWord32le
    wireLen <- getWord32le
    return $! PcapHeader timestampSec timestampUsec captureLen wireLen

data UdpHeader = UdpHeader
  { udpSrcPort    :: {-# UNPACK #-} !W.Word16
  , udpDestPort   :: {-# UNPACK #-} !W.Word16
  , udpPayloadLen :: {-# UNPACK #-} !W.Word16
  , udpCheckSum   :: {-# UNPACK #-} !W.Word16
  } deriving (Show)

getUdpHeader :: Get UdpHeader
getUdpHeader = let consume = getWord16be in
    UdpHeader <$> consume <*> consume <*> consume <*> consume

data QuotePacket = QuotePacket
    { quoteBidPrices :: [BL.ByteString]
    , quoteAskPrices :: [BL.ByteString]
    } deriving (Show)

-- parseQuoteDataPacket :: Get QuotePacket
-- parseQuoteDataPacket = do
--     skip
--         ( 12 -- Issue Code 
--         + 3 -- Issue seq no
--         + 2 -- Market status type
--         + 7 -- total bid quote volume
--         )
--     b1 <- getLazyByteString 5
--     skip 7
--     b2 <- getLazyByteString 5
--     skip 7
--     b3 <- getLazyByteString 5
--     skip 7
--     b4 <- getLazyByteString 5
--     skip 7
--     b5 <- getLazyByteString 5
--     skip (7 + 7)
--     a1 <- getLazyByteString 5
--     skip 7
--     a2 <- getLazyByteString 5
--     skip 7
--     a3 <- getLazyByteString 5
--     skip 7
--     a4 <- getLazyByteString 5
--     skip 7
--     a5 <- getLazyByteString 5
--     return $! QuotePacket [b1, b2, b3, b4, b5] [a1, a2, a3, a4, a5]

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
        else do -- Find a way to skip
            skip ethernetIPv4HeaderLen
            _ <- print <$> getUdpHeader -- suppressed
            quotePacket <- getLazyByteString 5
            if quotePacket /= "B6034"
                then do
                    print <$> quotePacket
                    -- skip packetLen
                    -- return $ print packetLen
                else do
                    return $ print BL.pack "B6034"
            -- _ <- print <$> parseQuoteDataPacket
