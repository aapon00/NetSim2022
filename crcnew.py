#The Bayesian Information Criterion, or BIC for short, is a method for scoring and selecting a model.
# It is named for the field of study from which it was derived: Bayesian probability and inference.
# Like AIC, it is appropriate for models fit under the maximum likelihood estimation framework
#Lower AIC values indicate a better-fit model

import pandas as pd
from fitter import Fitter
import argparse

ap = argparse.ArgumentParser()

ap.add_argument('-data','--csv1', type=str  , help='csv file')
args = ap.parse_args()

df= pd.read_csv(args.csv1)

def main(csv1):
    my_dict = {}
    for i in df["DestinationIP_&_Port"].unique():
        df1 = df.loc[df['DestinationIP_&_Port'] == i]
        c_list = df1.Time_Stamp.values.tolist()
        c_list1 = [c_list[i + 1] - c_list[i] for i in range(len(c_list) - 1)]
        df2 = pd.DataFrame({'weibull': c_list1})
        df3 = df2["weibull"]

        f = Fitter(df3, distributions=['gamma', 'lognorm', "beta", "burr", "norm"])
        f.fit()
        dist_best = f.get_best(method='sumsquare_error')
        my_dict[i] = dist_best


    return(my_dict)


if __name__ == '__main__':
    print(main(args.csv1))