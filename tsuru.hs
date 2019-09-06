module Main(main) where

import System.Environment (getArgs)
import Data.Binary.Get ()
import qualified Data.ByteString as B

main :: IO ()
main = do
    args <- getArgs
    parseArgs args
    where
        parseArgs [pcapFileName] = readPcapFile pcapFileName
        parseArgs [] = putStrLn "No input. Exit now."
        parseArgs _ = putStrLn "unimplemented"

-- Read quote market 
-- data MarketData = MarketData
-- { datatype :: 
-- }

readPcapFile :: String -> IO ()
readPcapFile fileName = do 
    content <- B.readFile fileName
    print . B.unpack $ content