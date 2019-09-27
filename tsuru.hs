{-# LANGUAGE OverloadedStrings #-}

module Main(main) where

-- import           Control.Monad.Extra  (ifM)
import           Data.Binary.Get               (Decoder (..), Get,
                                                getLazyByteString, getWord16be,
                                                getWord32le, runGetIncremental,
                                                skip)
import qualified Data.ByteString               as B
import qualified Data.ByteString.Lazy          as BL
import qualified Data.ByteString.Lazy.Internal as BL
import           Data.Maybe                    (fromJust, isJust)
import qualified Data.Word                     as W
import           GHC.Int                       (Int64)
import           System.Environment            (getArgs)

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

data UdpHeader = UdpHeader
  { udpSrcPort    :: {-# UNPACK #-} !W.Word16
  , udpDestPort   :: {-# UNPACK #-} !W.Word16
  , udpPayloadLen :: {-# UNPACK #-} !W.Word16
  , udpCheckSum   :: {-# UNPACK #-} !W.Word16
  } deriving (Show)

data QuotePacket = QuotePacket
  { quoteBidPrices :: [BL.ByteString]
  , quoteAskPrices :: [BL.ByteString]
  } deriving (Show)

main :: IO ()
main = do
    args <- getArgs
    parseArgs args
    where
        parseArgs [pcapFileName] = readPcapFile pcapFileName
        parseArgs []             = putStrLn "No input. Exit now."
        parseArgs _              = putStrLn "unimplemented"

-- https://wiki.wireshark.org/Development/LibpcapFileFormat
readPcapFile :: String -> IO ()
readPcapFile fileName = do
    pcap <- BL.readFile fileName
    let payloadWithoutPcapGlobalHeader = BL.drop pcapGlobalHeaderLen pcap
    print $ incrementGetQuoteData payloadWithoutPcapGlobalHeader

incrementGetQuoteData :: BL.ByteString -> [QuotePacket]
incrementGetQuoteData input = fmap fromJust . filter isJust $ go decoder input
    where
        decoder = runGetIncremental getQuoteData
        go :: Decoder (Maybe QuotePacket) -> BL.ByteString -> [Maybe QuotePacket]
        go (Done leftover _consumed quotePacket) input' = quotePacket : go decoder (BL.chunk leftover input')
        go (Partial k) input' = go (k . takeHeadChunk $ input') (dropHeadChunk input')
        go (Fail _leftover _consumed _msg) _input = [] -- error . show $ B.take 50 _leftover

takeHeadChunk :: BL.ByteString -> Maybe B.ByteString
takeHeadChunk lbs =
    case lbs of
        (BL.Chunk bs _) -> Just bs
        _               -> Nothing

dropHeadChunk :: BL.ByteString -> BL.ByteString
dropHeadChunk lbs =
    case lbs of
        (BL.Chunk _ lbs') -> lbs'
        _                 -> BL.Empty

getQuoteData :: Get (Maybe QuotePacket)
getQuoteData = do
    pcapHeader <- getPcapHeader
    let packetLen = fromIntegral $ pcapCaptureLen pcapHeader :: Int

    if packetLen <= 0
        then do
            skip packetLen
            return Nothing
        else do
            skip ethernetIPv4HeaderLen
            -- udpHeader <- getUdpHeader
            _ <- getUdpHeader
            quotePacket <- getLazyByteString 5
            if quotePacket /= "B6034"
                then do
                    skip packetLen
                    return Nothing
                else do
                    marketData <- parseQuoteDataPacket
                    return (Just marketData)


-- get binary -------------------------

getPcapHeader :: Get PcapHeader
getPcapHeader = do
    timestampSec <- getWord32le
    timestampUsec <- getWord32le
    captureLen <- getWord32le
    wireLen <- getWord32le
    return $! PcapHeader timestampSec timestampUsec captureLen wireLen

getUdpHeader :: Get UdpHeader
getUdpHeader = do
    srcPort <- getWord16be
    destPort <- getWord16be
    payloadLen <- getWord16be
    checksum <- getWord16be
    return $! UdpHeader srcPort destPort payloadLen checksum

parseQuoteDataPacket :: Get QuotePacket
parseQuoteDataPacket = do
    skip
        ( 12 -- Issue Code
        + 3 -- Issue seq no
        + 2 -- Market status type
        + 7 -- total bid quote volume
        )
    b1 <- getLazyByteString 5
    skip 7
    b2 <- getLazyByteString 5
    skip 7
    b3 <- getLazyByteString 5
    skip 7
    b4 <- getLazyByteString 5
    skip 7
    b5 <- getLazyByteString 5
    skip (7 + 7)
    a1 <- getLazyByteString 5
    skip 7
    a2 <- getLazyByteString 5
    skip 7
    a3 <- getLazyByteString 5
    skip 7
    a4 <- getLazyByteString 5
    skip 7
    a5 <- getLazyByteString 5
    skip 50
    return $! QuotePacket [b1, b2, b3, b4, b5] [a1, a2, a3, a4, a5]
