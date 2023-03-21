use super::{DataSet, DataSetMessage};

/// An entity receiving DataSetMessages from a MessageOrientedMiddleware. It extracts a DataSetMessage from a NetworkMessage
/// and decodes the DataSetMessage to a DataSet for further processing in the Subscriber
trait DataSetReader {
    /// Reads a data set message to a data set
    fn read<T>(&self, dsm: Box<T>) -> Option<DataSet> where T: DataSetMessage;
}
