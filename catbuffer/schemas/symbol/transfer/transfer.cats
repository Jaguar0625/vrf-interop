import "transaction.cats"

# binary layout for a transfer transaction
struct TransferTransactionBody
	# recipient address
	recipientAddress = UnresolvedAddress

	# size of attached message
	messageSize = uint16

	# number of attached mosaics
	mosaicsCount = uint8

	# reserved padding to align mosaics on 8-byte boundary
	transferTransactionBody_Reserved1 = make_reserved(uint32, 0)

	# reserved padding to align mosaics on 8-byte boundary
	transferTransactionBody_Reserved2 = make_reserved(uint8, 0)

	# attached mosaics
	mosaics = array(UnresolvedMosaic, mosaicsCount, sort_key=mosaicId)

	# attached message
	message = array(uint8, messageSize)

# binary layout for a non-embedded transfer transaction
struct TransferTransaction
	transaction_version = make_const(uint8, 1)
	transaction_type = make_const(TransactionType, transfer)

	inline Transaction
	inline TransferTransactionBody

# binary layout for an embedded transfer transaction
struct EmbeddedTransferTransaction
	transaction_version = make_const(uint8, 1)
	transaction_type = make_const(TransactionType, transfer)

	inline EmbeddedTransaction
	inline TransferTransactionBody
