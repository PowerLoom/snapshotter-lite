source .env

echo "setting up codebase...";

rm -rf submission-sequencer;
git clone https://github.com/PowerLoom/submission-sequencer.git;
cd ./submission-sequencer;
git checkout no_dashboard;
cd ..;

echo "bootstrapping complete!";